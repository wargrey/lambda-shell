#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

(require digimon/thread)

(require racket/format)
(require racket/string)
(require racket/path)
(require racket/file)
(require racket/port)

(require "path.rkt")

(require/typed racket/port
               [input-port-append (-> Boolean Input-Port * Input-Port)])

(define scp-exit-status : (Parameterof Index) (make-parameter 0))

(struct scp-file
  ([mtime : Nonnegative-Fixnum]
   [atime : Nonnegative-Fixnum]
   [mode : Nonnegative-Fixnum]
   [size : Natural]
   [basename : Path-String])
  #:type-name SCP-File
  #:transparent
  #:mutable)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp : (-> String String Index SSH-Configuration Void)
  (lambda [source target port rfc]
    (define-values (suser shost sport spath) (scp-file-path source port))
    (define-values (tuser thost tport tpath) (scp-file-path target port))

    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/srcin /dev/srcout) (make-pipe))
      (define-values (/dev/destin /dev/destout) (make-pipe))
      (define-values (&rstatus &wstatus) (values (box 1) (box 1)))
      
      (define rthread : Thread
        (thread (λ [] (parameterize ([scp-exit-status 1])
                        (with-handlers ([exn:break? void]
                                        [exn? (λ [[e : exn]] (fprintf (current-error-port) "scp-reader: ~a~n" (exn-message e)))])
                          (cond [(not shost) (scp-local-read spath /dev/destin /dev/srcout rfc)]
                                [else (scp-read suser shost sport spath rfc /dev/destin /dev/srcout)]))
                        (set-box! &rstatus (scp-exit-status))))))
      
      (define wthread : Thread
        (thread (λ [] (parameterize ([scp-exit-status 1])
                        (with-handlers ([exn:break? void]
                                        [exn? (λ [[e : exn]] (fprintf (current-error-port) "rcp-writer: ~a~n" (exn-message e)))])
                          (cond [(not thost) (scp-local-write tpath /dev/srcin /dev/destout rfc)]
                                [else (scp-write tuser thost tport tpath rfc /dev/srcin /dev/destout)]))
                        (set-box! &wstatus (scp-exit-status))))))

      (let ([thds (list rthread wthread)])
        (with-handlers ([exn? void])
          (define who (apply sync/enable-break thds))
          
          (cond [(eq? who rthread) (when (zero? (unbox &rstatus)) (sync/enable-break wthread))]
                [(eq? who wthread) (when (zero? (unbox &wstatus)) (sync/enable-break rthread))]))
        
        (thread-safe-kill thds)
        (custodian-shutdown-all (current-custodian))
        (exit (+ (unbox &rstatus) (unbox &wstatus)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-read : (-> Symbol String Index Path-String SSH-Configuration Input-Port Output-Port Void)
  (lambda [user host port path rfc /dev/destin /dev/destout]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc #:name 'r))
    (define scp-reader : SSH-Session (ssh-user-login sshd user))
    (define connection : SSH-Application (sync/enable-break (ssh-session-service-ready-evt scp-reader)))
    
    (when (ssh-connection-application? connection)
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write scp-reader open-session-message)
      
      (let ([chin (ssh-session-read scp-reader)])
        (when (ssh-application-channel? chin)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close scp-reader (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))
            
            (ssh-channel-request-exec chin "scp -f ~a" path)
            
            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies chin 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port chin))
              
              (let scp-recv ()
                (define in (sync/enable-break /dev/scpin /dev/destin (ssh-channel-extended-data-evt chin)))
                
                (cond [(eq? in /dev/scpin)
                       (define size (read-bytes-avail! parcel /dev/scpin))

                       (when (index? size)
                         (write-bytes parcel /dev/destout 0 size)
                         (scp-recv))]
                      [(eq? in /dev/destin)
                       (define size (read-bytes-avail! parcel /dev/destin))
    
                       (cond [(index? size)
                              (write-bytes parcel /dev/scpout 0 size)
                              (scp-recv)]
                             [else (close-output-port /dev/scpout)])]
                      [(pair? in)
                       (fprintf (current-error-port) "~a~n" (cdr in))
                       (scp-recv)]))

              (scp-exit-status (ssh-channel-program-wait chin))
              (ssh-channel-close chin)
              (ssh-channel-wait chin)
              (ssh-session-close scp-reader "scp read"))))))
        
    (ssh-session-close scp-reader "something is wrong")))

(define scp-write : (-> Symbol String Index Path-String SSH-Configuration Input-Port Output-Port Void)
  (lambda [user host port path rfc /dev/srcin /dev/srcout]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc #:name 'w))
    (define scp-writer : SSH-Session (ssh-user-login sshd user))
    (define connection : SSH-Application (sync/enable-break (ssh-session-service-ready-evt scp-writer)))
    
    (when (ssh-connection-application? connection)
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write scp-writer open-session-message)
      
      (let ([chout (ssh-session-read scp-writer)])
        (when (ssh-application-channel? chout)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close scp-writer (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))

            (ssh-channel-request-exec chout "scp -t ~a" path)

            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies chout 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port chout))
              (define srcfile : SCP-File (scp-file 0 0 0 0 path))
              
              (let scp-send ([round : Byte 0])
                (define scpin (sync/enable-break /dev/scpin (ssh-channel-extended-data-evt chout)))

                (cond [(input-port? scpin)
                       (define ack : (U Byte Void) (scp-port-write parcel /dev/scpin /dev/scpout /dev/srcin /dev/srcout round srcfile))
                       (when (byte? ack) (scp-send ack))]
                      [(pair? scpin)
                       (fprintf (current-error-port) "~a~n" (cdr scpin))
                       (scp-send round)]))

              (scp-exit-status (ssh-channel-program-wait chout))
              (ssh-channel-wait chout)
              (ssh-session-close scp-writer "scp written"))))))
        
    (ssh-session-close scp-writer "something is wrong")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-local-read : (-> Path-String Input-Port Output-Port SSH-Configuration Void)
  (lambda [path /dev/scpin /dev/scpout rfc]
    (define parcel : Bytes (make-bytes ($ssh-channel-packet-capacity rfc)))
    (define mtime : Nonnegative-Fixnum (file-or-directory-modify-seconds path))
    (define mode : Nonnegative-Fixnum (file-or-directory-permissions path 'bits))
    (define srcfile : SCP-File (scp-file mtime mtime mode (file-size path) path))
    (define /dev/srcin : Input-Port
      (input-port-append #true
                         (open-input-string (format "T~a 0 ~a 0~n" mtime mtime))
                         (open-input-string (format "C~a ~a ~a~n" (~r mode #:base 8 #:min-width 4 #:pad-string "0")
                                              (scp-file-size srcfile) (file-name-from-path path)))
                         (open-input-file path)))
    
    (let stdio : Void ([round : Byte 0])
      (define ack : (U Byte Void) (scp-port-write parcel /dev/scpin /dev/scpout /dev/srcin #false round srcfile))
      (when (byte? ack) (stdio ack)))

    (close-input-port /dev/srcin)
    (scp-exit-status 0)))

(define scp-local-write : (-> Path-String Input-Port Output-Port SSH-Configuration Void)
  (lambda [path /dev/scpin /dev/scpout rfc]
    (define parcel : Bytes (make-bytes ($ssh-channel-packet-capacity rfc)))
    (define destfile : SCP-File (scp-file 0 0 0 0 path))

    (write-byte 0 /dev/scpout)
    
    (let stdio : Void ([round : Byte 0])
      (define scpin (sync/enable-break /dev/scpin))

      (case round
        [(0) (let ([T (read-char /dev/scpin)]
                   [line (read-line /dev/scpin)])
               (when (string? line)
                 (case T
                   [(#\T) (scp-port-parse-time line destfile) (write-byte 0 /dev/scpout) (stdio 1)]
                   [(#\C) (scp-port-parse-info line destfile) (write-byte 0 /dev/scpout) (stdio 2)])))]
        [(1) (let ([T (read-char /dev/scpin)]
                   [line (read-line /dev/scpin)])
               (when (and (eq? T #\C) (string? line))
                 (scp-port-parse-info line destfile)
                 (write-byte 0 /dev/scpout)
                 (stdio 2)))]
        [(2) (let ([capacity (bytes-length parcel)]
                   [basename (scp-file-basename destfile)])
               (define destpath : Path-String
                 (cond [(directory-exists? path) (build-path path basename)]
                       [else path]))
               (make-parent-directory* destpath)
               (call-with-output-file* destpath #:exists 'truncate/replace
                 (λ [[/dev/destout : Output-Port]] : Void
                   (let scpio ([rest : Integer (scp-file-size destfile)])
                     (if (> rest 0)
                         (let ([size (read-bytes-avail! parcel /dev/scpin 0 (min capacity rest))])
                           (when (index? size)
                             (write-bytes parcel /dev/destout 0 size)
                             (scpio (- rest size))))
                         (let ([mtime (scp-file-mtime destfile)]
                               [mode (scp-file-mode destfile)])
                           (when (> mtime 0) (file-or-directory-modify-seconds destpath mtime void))
                           (file-or-directory-permissions destpath mode)
                           (write-byte 0 /dev/scpout)
                           (stdio 3)))))))]
        [(3) (let ([feedback (read-byte /dev/scpin)])
               (when (byte? feedback)
                 (scp-exit-status feedback)))]))

    (close-output-port /dev/scpout)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-port-parse-time : (-> String SCP-File Void)
  (lambda [Tline scpfile]
    (define tokens : (Listof Nonnegative-Fixnum) (filter nonnegative-fixnum? (map string->number (string-split Tline))))
    
    (cond [(not (and (pair? tokens) (= (length tokens) 4))) (error 'scp-port-parse-time "invalid T line: T~a" Tline)]
          [else (set-scp-file-mtime! scpfile (list-ref tokens 0))
                (set-scp-file-atime! scpfile (list-ref tokens 1))])))

(define scp-port-parse-info : (-> String SCP-File Void)
  (lambda [Cline scpfile]
    (define tokens : (Listof String) (string-split Cline))
    
    (cond [(not (and (pair? tokens) (>= (length tokens) 3))) (error 'scp-port-parse-info "invalid C line: C~a" Cline)]
          [else (let ([mode (string->number (car tokens) 8)]
                      [size (string->number (cadr tokens))])
                  (cond [(not (and (nonnegative-fixnum? mode) (exact-nonnegative-integer? size))) (error 'scp-port-parse-info "invalid C line: C~a" Cline)]
                        [else (let ([basename (string-join (cddr tokens) " ")])
                                (set-scp-file-mode! scpfile mode)
                                (set-scp-file-size! scpfile size)
                                (set-scp-file-basename! scpfile basename))]))])))

(define scp-port-write : (-> Bytes Input-Port Output-Port Input-Port (Option Output-Port) Byte SCP-File (U Byte Void))
  (lambda [parcel /dev/scpin /dev/scpout /dev/srcin /dev/srcout round srcfile]
    (define size (read-bytes-avail! parcel /dev/scpin))

    (displayln size)
    (when (index? size)
      (let ([ack? (and (= size 1) (eq? (bytes-ref parcel 0) 0))])
        
        (when (and /dev/srcout (= size 1))
          (write-byte (bytes-ref parcel 0) /dev/srcout))
        
        (unless (not ack?)
          (case round
            [(0) (let ([T (read-char /dev/srcin)]
                       [line (read-line /dev/srcin)])
                   (when (and (char? T) (string? line))
                     (scp-port-write-info-line T line /dev/scpout)
                     (case T
                       [(#\T) (scp-port-parse-time line srcfile) 1]
                       [(#\C) (scp-port-parse-info line srcfile) 2])))]
            [(1) (let ([T (read-char /dev/srcin)]
                       [line (read-line /dev/srcin)])
                   (when (and (char? T) (eq? T #\C) (string? line))
                     (scp-port-write-info-line T line /dev/scpout)
                     (scp-port-parse-info line srcfile)
                     2))]
            [(2) (let ([capacity (bytes-length parcel)])
                   (let scpio : (U Byte Void) ([rest : Integer (scp-file-size srcfile)])
                     (if (> rest 0)
                         (let ([size (read-bytes-avail! parcel /dev/srcin 0 (min capacity rest))])
                           (when (index? size)
                             (write-bytes parcel /dev/scpout 0 size)
                             (scpio (- rest size))))
                         (and (write-byte 0 /dev/scpout)
                              (close-output-port /dev/scpout)
                              3))))]))))))

(define scp-port-write-info-line : (-> Char String Output-Port Void)
  (lambda [T line /dev/scpout]
    (write-char T /dev/scpout)
    (write-string line /dev/scpout)
    (newline /dev/scpout)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define nonnegative-fixnum? : (-> Any Boolean : #:+ Nonnegative-Fixnum)
  (lambda [v]
    (and (fixnum? v) (>= v 0))))
