#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/connection)

(define scp : (-> SSH-Port Void)
  (lambda [sshc]
    (parameterize ([current-peer-name (ssh-port-peer-name sshc)])
      (define maybe-service : SSH-Maybe-Service (ssh-user-identify sshc 'wargrey))

      (when (pair? maybe-service)
        (displayln maybe-service)))))
