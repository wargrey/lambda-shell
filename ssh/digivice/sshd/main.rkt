#lang typed/racket/base

(provide (all-defined-out))

(require ssh/base)
(require ssh/authentication)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define sshd-serve : (-> SSH-Port (Listof Symbol) Void)
  (lambda [sshc services]
    (parameterize ([current-peer-name (ssh-port-peer-name sshc)])
      (with-handlers ([exn:fail? (λ [[e : exn]] (ssh-shutdown sshc 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
        (define maybe-user (ssh-user-authenticate sshc services))
        
        (when (ssh-user? maybe-user)
          (let sync-read-display-loop ()
            (define datum (sync/enable-break (ssh-port-datum-evt sshc)))
            (unless (ssh-eof? datum)
              (sync-read-display-loop)))))
      
      (ssh-port-wait sshc))))
