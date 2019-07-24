#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

(require digimon/thread)

(require racket/format)
(require racket/string)
(require racket/path)
(require racket/port)

(require "path.rkt")

(require/typed racket/port
               [input-port-append (-> Boolean Input-Port * Input-Port)])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp : (-> String String Index SSH-Configuration Void)
  (lambda [source target port rfc]
    (define-values (suser shost sport spath) (scp-file-path source port))
    (define-values (tuser thost tport tpath) (scp-file-path target port))

    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/srcin /dev/srcout) (make-pipe))
      (define-values (/dev/destin /dev/destout) (make-pipe))
      (define rthread : Thread
        (thread (λ [] (with-handlers ([exn:break? void]
                                      [exn? (λ [[e : exn]] (fprintf (current-error-port) "~a~n" (exn-message e)))])
                        (cond [(not shost) (scp-local-read spath /dev/destin /dev/srcout)]
                              [else (scp-read suser shost sport spath rfc /dev/destin /dev/srcout)])))))
      
      (define wthread : Thread
        (thread (λ [] (with-handlers ([exn:break? void]
                                      [exn? (λ [[e : exn]] (fprintf (current-error-port) "~a~n" (exn-message e)))])
                        (cond [(not thost) (scp-local-write tpath /dev/srcin /dev/destout)]
                              [else (scp-write tuser thost tport tpath rfc /dev/srcin /dev/destout)])))))
      
      (with-handlers ([exn? void])
        (sync/enable-break wthread))
      
      (thread-safe-kill (list rthread wthread))
      (custodian-shutdown-all (current-custodian)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-read : (-> Symbol String Index Path-String SSH-Configuration Input-Port Output-Port Void)
  (lambda [user host port path rfc /dev/stdin /dev/stdout]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc))
    (define-values (userlogin connection) (ssh-user-login sshd user))
    
    (when (and userlogin (ssh-connection-application? connection))
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write userlogin open-session-message)
      
      (let ([chin (ssh-session-read userlogin)])
        (when (ssh-application-channel? chin)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close userlogin (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))
            
            (ssh-channel-request-exec chin "scp -f ~a" path)
            
            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies chin 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port chin))

              (write-char #\null /dev/scpout)
              
              (let scp-recv ([acknowledgement : Index 0])
                (define scpin (sync/enable-break /dev/scpin (ssh-channel-extended-data-evt chin)))
                
                (cond [(input-port? scpin)
                       (case acknowledgement
                         [(0) (let* ([T (read-char scpin)]
                                     [Tline (read-line scpin)]
                                     [tokens (and (string? Tline) (string-split Tline))])
                                (unless (and (string? Tline)
                                             (eq? T #\T)
                                             (= (length tokens) 4)
                                             (andmap exact-nonnegative-integer? (map string->number tokens)))
                                  (error 'scp-read "invalid time info line: ~a~a" T Tline))
                                (write-char #\T /dev/stdout)
                                (write-string Tline /dev/stdout)
                                (newline /dev/stdout)
                                (write-char #\null /dev/scpout)
                                (scp-recv 1))]
                         [(1) (let* ([sign (read-char scpin)]
                                     [mode (read-string 4 scpin)]
                                     [size (read scpin)]
                                     [basename (read-line scpin)])
                                (unless (and (eq? sign #\C)
                                             (string? mode)
                                             (string->number mode 8)
                                             (exact-nonnegative-integer? size))
                                  (error 'scp-read "invalid file info line: ~a~a ~a~a" sign size basename))
                                (fprintf /dev/stdout "~a~a ~a~a~n" sign mode size basename)
                                (write-char #\null /dev/scpout)
                                (scp-recv 2))]
                         [else (let ([size (read-bytes-avail! parcel scpin)])
                                 (void))])]
                      [(pair? scpin)
                       (fprintf (current-error-port) "~a~n" (cdr scpin))
                       (scp-recv acknowledgement)]
                      [else (scp-recv acknowledgement)]))
              
              (ssh-channel-close chin)
              (ssh-channel-wait chin)
              (ssh-session-close userlogin "job done"))))
        
        (ssh-session-close userlogin "something is wrong")))))

(define scp-write : (-> Symbol String Index Path-String SSH-Configuration Input-Port Output-Port Void)
  (lambda [user host port path rfc /dev/srcin /dev/srcout]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc))
    (define-values (userlogin connection) (ssh-user-login sshd 'wargrey))
    
    (when (and userlogin (ssh-connection-application? connection))
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write userlogin open-session-message)
      
      (let ([chout (ssh-session-read userlogin)])
        (when (ssh-application-channel? chout)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close userlogin (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))
            
            (ssh-channel-request-exec chout "scp -t ~a" path)
            
            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies chout 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port chout))
              
              (let scp-send ([acknowledgement : Byte 0])
                (define scpin (sync/enable-break /dev/scpin (ssh-channel-extended-data-evt chout)))
                
                (cond [(input-port? scpin)
                       (define ack : (U Byte Void) (scp-port-write parcel /dev/scpin /dev/scpout /dev/srcin /dev/srcout acknowledgement))
                       
                       (when (byte? ack)
                         (scp-send ack))]
                      [(pair? scpin)
                       (fprintf (current-error-port) "~a~n" (cdr scpin))
                       (scp-send acknowledgement)]
                      [else (scp-send acknowledgement)]))

              (ssh-channel-close chout)
              (ssh-channel-wait chout)
              (ssh-session-close userlogin "job done"))))
        
        (ssh-session-close userlogin "something is wrong")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-local-read : (-> Path-String Input-Port Output-Port Void)
  (lambda [path /dev/scpin /dev/scpout]
    (define parcel : Bytes (make-bytes 4096))
    (define mtime : Nonnegative-Fixnum (file-or-directory-modify-seconds path))
    (define mode : Nonnegative-Fixnum (file-or-directory-permissions path 'bits))
    (define /dev/srcin : Input-Port
      (input-port-append #true
                         (open-input-string (format "T~a 0 ~a 0~n" mtime mtime))
                         (open-input-string (format "C~a ~a ~a~n" (~r mode #:base 8 #:min-width 4 #:pad-string "0")
                                              (file-size path) (file-name-from-path path)))
                         (open-input-file path)
                         (open-input-bytes (bytes 0))))
    
    (let stdio : Void ([acknowledgement : Byte 0])
      (define ack : (U Byte Void) (scp-port-write parcel /dev/scpin /dev/scpout /dev/srcin #false acknowledgement))

      (when (byte? ack)
        (stdio ack)))

    (close-input-port /dev/srcin)))

(define scp-local-write : (-> Path-String Input-Port Output-Port Void)
  (lambda [path /dev/win /dev/rout]
    (define /dev/stdout : Output-Port (open-output-file path))
    (define parcel : Bytes (make-bytes 4096))

    (let stdio : Void ()
      (define size (read-bytes-avail! parcel /dev/win))
      (when (index? size)
        (write-bytes parcel /dev/stdout 0 size)
        (stdio)))
    
    (close-input-port /dev/win)
    (close-output-port /dev/stdout)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-port-write : (-> Bytes Input-Port Output-Port Input-Port (Option Output-Port) Byte (U Byte Void))
  (lambda [parcel /dev/scpin /dev/scpout /dev/srcin /dev/srcout acknowledgement]
    (define size (read-bytes-avail! parcel /dev/scpin))
    
    (when (index? size)
      (let ([ack? (and (= size 1) (eq? (bytes-ref parcel 0) 0))])
        
        (when (and /dev/srcout (= size 1))
          (write-byte (bytes-ref parcel 0) /dev/srcout))
        
        (unless (not ack?)
          (case acknowledgement
            [(0) (let ([Tline (read-line /dev/srcin)])
                   (when (string? Tline)
                     (write-string Tline /dev/scpout)
                     (newline /dev/scpout)
                     1))]
            [(1) (let ([Fline (read-line /dev/srcin)])
                   (when (string? Fline)
                     (write-string Fline /dev/scpout)
                     (newline /dev/scpout)
                     2))]
            [(2) (let scpio : (U Byte Void) ()
                   (define size (read-bytes-avail! parcel /dev/srcin))
                   (cond [(index? size)
                          (write-bytes parcel /dev/scpout 0 size)
                          (scpio)]
                         [else (close-output-port /dev/scpout) 3]))]
            [else (void)]))))))
