#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

(define scp : (-> SSH-Port Void)
  (lambda [sshd]
    (parameterize ([current-peer-name (ssh-port-peer-name sshd)])
      (define session : (Option SSH-Session) (ssh-user-login sshd 'wargrey))

      (unless (not session)
        (ssh-session-ignore session "test")
        (ssh-session-wait session)))))
