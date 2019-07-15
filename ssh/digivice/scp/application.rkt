#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)

(define scp : (-> SSH-Port Void)
  (lambda [sshc]
    (parameterize ([current-peer-name (ssh-port-peer-name sshc)])
      (ssh-user-identify sshc 'wargrey)
      (void))))
