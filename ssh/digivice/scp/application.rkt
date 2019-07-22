#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp : (-> SSH-Port Void)
  (lambda [sshd]
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
            (ssh-channel-request-exec channel "scp")
            (ssh-channel-wait-replies channel 1)
            (ssh-channel-close channel)

            (ssh-session-wait userlogin))

          (ssh-session-close userlogin "something is wrong"))))))
