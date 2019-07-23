#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

(require digimon/thread)

(require racket/format)
(require racket/path)

(require "path.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp : (-> String String Index SSH-Configuration Void)
  (lambda [source target port rfc]
    (define-values (suser shost sport spath) (scp-file-path source port))
    (define-values (tuser thost tport tpath) (scp-file-path target port))

    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/stdin /dev/stdout) (make-pipe))
      (define rthread : Thread
        (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (fprintf (current-error-port) "~a~n" (exn-message e)))])
                        (cond [(not shost) (scp-local-read spath /dev/stdout)]
                              [else (scp-read suser shost sport spath rfc /dev/stdout)])))))
      
      (define wthread : Thread
        (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (fprintf (current-error-port) "~a~n" (exn-message e)))])
                        (cond [(not thost) (scp-local-write tpath /dev/stdin)]
                              [else (scp-write tuser thost tport tpath rfc /dev/stdin)])))))
      
      (with-handlers ([exn? void])
        (sync/enable-break wthread))
      
      (thread-safe-kill (list rthread wthread))
      (custodian-shutdown-all (current-custodian)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-read : (-> Symbol String Index Path-String SSH-Configuration Output-Port Void)
  (lambda [user host port path rfc /dev/stdout]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc))
    (define-values (userlogin connection) (ssh-user-login sshd user))
    
    (when (and userlogin (ssh-connection-application? connection))
      (define rfc : SSH-Configuration (ssh-transport-preference sshd))
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write userlogin open-session-message)
      
      (let ([channel (ssh-session-read userlogin)])
        (when (ssh-application-channel? channel)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close userlogin (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))
            
            (ssh-channel-request-exec channel "scp -t ~a" (find-system-path 'temp-dir))
            
            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies channel 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port channel))
              
              (let scp-send ([acknowledgement : Byte 0])
                (define scpin (sync/enable-break /dev/scpin (ssh-channel-extended-data-evt channel)))
                
                (cond [(input-port? scpin)
                       (define size (read-bytes-avail! parcel scpin))
                       
                       (when (index? size)
                         (let ([ack? (and (= size 1) (eq? (bytes-ref parcel 0) 0))])
                           (unless (not ack?)
                             (case acknowledgement
                               [(0) (fprintf /dev/scpout "T~a 0 ~a 0~n" (current-seconds) (current-seconds)) (scp-send 1)] ; mtime and atime
                               [(1) (fprintf /dev/scpout "C0~a ~a ~a~n" (number->string #o777 8) (expt 2 33) "scp.rkt.test") (scp-send 2)] ; mode, size, basename
                               [else (write (make-bytes (expt 2 33)) /dev/scpout) (scp-send acknowledgement)]))))]
                      [(pair? scpin)
                       (fprintf (current-error-port) "~a~n" (cdr scpin))
                       (scp-send acknowledgement)]
                      [else (scp-send acknowledgement)]))
              
              (ssh-channel-close channel)
              (ssh-channel-wait channel)
              (ssh-session-close userlogin "job done"))))
        
        (ssh-session-close userlogin "something is wrong")))))

(define scp-write : (-> Symbol String Index Path-String SSH-Configuration Input-Port Void)
  (lambda [user host port path rfc /dev/stdin]
    (define sshd : SSH-Port (ssh-connect host port #:configuration rfc))
    (define-values (userlogin connection) (ssh-user-login sshd 'wargrey))
    
    (when (and userlogin (ssh-connection-application? connection))
      (define rfc : SSH-Configuration (ssh-transport-preference sshd))
      (define open-session-message : SSH-MSG-CHANNEL-OPEN
        (ssh-connection-open-channel-message connection 'session
                                             #:window-size ($ssh-channel-initial-window-size rfc)
                                             #:packet-capacity ($ssh-channel-packet-capacity rfc)))
      
      (ssh-session-write userlogin open-session-message)
      
      (let ([channel (ssh-session-read userlogin)])
        (when (ssh-application-channel? channel)
          (with-handlers ([exn? (λ [[e : exn]] (ssh-session-close userlogin (exn-message e)))])
            (define parcel (make-bytes ($ssh-channel-packet-capacity rfc)))
            
            (ssh-channel-request-exec channel "scp -t ~a" (find-system-path 'temp-dir))
            
            (when (andmap (λ [v] (eq? v #true)) (ssh-channel-wait-replies channel 1))
              (define-values (/dev/scpin /dev/scpout) (ssh-channel-stdio-port channel))
              (define mtime (read-bytes-line /dev/stdin))
              (define finfo (read-bytes-line /dev/stdin))
              
              (let scp-send ([acknowledgement : Byte 0])
                (define scpin (sync/enable-break /dev/scpin (ssh-channel-extended-data-evt channel)))
                
                (cond [(input-port? scpin)
                       (define size (read-bytes-avail! parcel scpin))
                       
                       (when (index? size)
                         (let ([ack? (and (= size 1) (eq? (bytes-ref parcel 0) 0))])
                           (unless (not ack?)
                             (case acknowledgement
                               [(0) (fprintf /dev/scpout "~a~n" mtime) (scp-send 1)]
                               [(1) (fprintf /dev/scpout "~a~n" finfo) (scp-send 2)]
                               [else (let scpio : Void ()
                                       (define size (read-bytes-avail! parcel /dev/stdin))
                                       (when (index? size)
                                         (write-bytes parcel /dev/scpout 0 size)
                                         (scpio)))]))))]
                      [(pair? scpin)
                       (fprintf (current-error-port) "~a~n" (cdr scpin))
                       (scp-send acknowledgement)]
                      [else (scp-send acknowledgement)]))
              
              (ssh-channel-close channel)
              (ssh-channel-wait channel)
              (ssh-session-close userlogin "job done"))))
        
        (ssh-session-close userlogin "something is wrong")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-local-read : (-> Path-String Output-Port Void)
  (lambda [path /dev/stdout]
    (define /dev/stdin : Input-Port (open-input-file path))
    (define parcel : Bytes (make-bytes 4096))
    (define mtine : Nonnegative-Fixnum (file-or-directory-modify-seconds path))
    (define mode : Nonnegative-Fixnum (file-or-directory-permissions path 'bits))

    (fprintf /dev/stdout "T~a 0 ~a 0~n" mtine mtine)
    (fprintf /dev/stdout "C~a ~a ~a~n" (~r mode #:base 8 #:min-width 4 #:pad-string "0") (file-size path) (file-name-from-path path))

    (let stdio : Void ()
      (define size (read-bytes-avail! parcel /dev/stdin))
      (when (index? size)
        (write-bytes parcel /dev/stdout 0 size)
        (stdio)))

    (close-input-port /dev/stdin)
    (close-output-port /dev/stdout)))

(define scp-local-write : (-> Path-String Input-Port Void)
  (lambda [path /dev/stdin]
    (define /dev/stdout : Output-Port (open-output-file path))
    (define parcel : Bytes (make-bytes 4096))

    (let stdio : Void ()
      (define size (read-bytes-avail! parcel /dev/stdin))
      (when (index? size)
        (write-bytes parcel /dev/stdout 0 size)
        (stdio)))
    
    (close-input-port /dev/stdin)
    (close-output-port /dev/stdout)))
