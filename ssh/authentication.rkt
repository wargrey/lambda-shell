#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out) SSH-Maybe-User)

(require racket/port)

(require "digitama/authentication.rkt")
(require "digitama/authentication/message.rkt")

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

(define ssh-user-authenticate : (-> SSH-Port [#:services (SSH-Name-Listof* SSH-Service#)] [#:methods (SSH-Name-Listof* SSH-Authentication#)] SSH-Maybe-User)
  (lambda [sshc #:services [services (ssh-registered-services)] #:methods [all-methods (ssh-authentication-methods)]]
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define timeout : Index ($ssh-userauth-timeout rfc))
    (define limit : Index ($ssh-userauth-retry rfc))

    (userauth-timeout sshc (λ [] (userauth-authenticate sshc services all-methods limit)) timeout)))

(define ssh-user-authenticate/none : (-> SSH-Port [#:services (SSH-Name-Listof* SSH-Service#)] SSH-Maybe-User)
  (lambda [sshc #:services [services (ssh-registered-services)]]
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define timeout : Index ($ssh-userauth-timeout rfc))
    (define limit : Index ($ssh-userauth-retry rfc))
    
    (userauth-timeout sshc (λ [] (userauth-none sshc services limit)) timeout)))
