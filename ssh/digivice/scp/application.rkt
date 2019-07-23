#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp : (-> String String Index SSH-Configuration Void)
  (lambda [source target port rfc]
    (define sshd : SSH-Port (ssh-connect source port #:configuration rfc))
    (parameterize ([current-peer-name (ssh-port-peer-name sshd)]
                   [current-custodian (ssh-custodian sshd)])
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
                (let scp-send ([acknowledged : Boolean #false])
                  (define scpin (sync/enable-break (ssh-channel-data-evt channel) (ssh-channel-extended-data-evt channel)))
                  
                  (cond [(input-port? scpin)
                         (define size (read-bytes-avail! parcel scpin))
                         
                         (when (index? size)
                           (if (not acknowledged)
                               (let ([ack? (and (= size 1) (eq? (bytes-ref parcel 0) #\null))])
                                 (unless (not ack?)
                                   (void))
                                 #;(scp-send ack?))
                               (and (writeln (subbytes parcel 0 size))
                                    (scp-send acknowledged))))]
                        [(pair? scpin)
                         (fprintf (current-error-port) "~a~n" (cdr scpin))
                         (scp-send acknowledged)]
                        [else (scp-send acknowledged)]))
                
                (ssh-channel-close channel)
                (ssh-channel-close channel)
                (ssh-channel-wait channel)
                (ssh-session-close userlogin "job done"))))

          (ssh-session-close userlogin "something is wrong"))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-file-path : (-> String Index SSH-Configuration (U SSH-Port Path-String))
  (lambda [path port rfc]
    path))
