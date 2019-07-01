#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))
(provide (all-from-out "digitama/authentication/datatype.rkt"))

(require racket/port)

(require "digitama/authentication.rkt")
(require "digitama/authentication/message.rkt")
(require "digitama/authentication/datatype.rkt")

(require "datatype.rkt")
(require "transport.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;; register builtin assignments for authentication methods
(require "digitama/assignment/authentication.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-request : (->* (SSH-Port Symbol) (Symbol) (U SSH-EOF True))
  (lambda [sshd username [service 'ssh-connection]]
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshd #false)])
      (define datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (authenticate (ssh-authentication-datum-evt sshd #false))]))))

(define ssh-user-authenticate : (-> SSH-Port (Listof Symbol) [#:methods (SSH-Name-Listof* SSH-Authentication#)] (U SSH-EOF SSH-User Void))
  (lambda [sshc services #:methods [all-methods (ssh-authentication-methods)]]
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define timeout : Index ($ssh-userauth-timeout rfc))
    (define limit : Index ($ssh-userauth-retry rfc))

    (cond [(= timeout 0) (userauth-authenticate sshc services all-methods limit)]
          [else (parameterize ([current-custodian (make-custodian)])
                  (let-values ([(/dev/stdin /dev/stdout) (make-pipe-with-specials)])
                  (define ghostcat : Thread (thread (λ [] (write-special (userauth-authenticate sshc services all-methods limit) /dev/stdout))))
                  
                  (let ([datum (sync/timeout/enable-break timeout (wrap-evt /dev/stdin (λ _ (read-byte-or-special /dev/stdin))))])
                    (custodian-shutdown-all (current-custodian))
                    (thread-wait ghostcat)
                    
                    (cond [(or (ssh-user? datum) (ssh-eof? datum) (void? datum)) datum]
                          [else (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT "authentication timeout")]))))])))
