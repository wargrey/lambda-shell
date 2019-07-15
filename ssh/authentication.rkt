#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out) SSH-Maybe-User SSH-Maybe-Service)

(require racket/port)

(require "digitama/authentication.rkt")

(require "datatype.rkt")
(require "transport.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;; register builtin assignments for authentication methods
(require "digitama/assignment/authentication.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-identify : (->* (SSH-Port Symbol)
                                 (Symbol #:services (SSH-Name-Listof* SSH-Service#) #:methods (SSH-Name-Listof* SSH-Authentication#))
                                 SSH-Maybe-Service)
  (lambda [sshd username [service 'ssh-connection] #:services [services (ssh-registered-services)] #:methods [all-methods (ssh-authentication-methods)]]
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (exn-message e)))])
      (define maybe-service : (Option (SSH-Nameof SSH-Service#)) (assq service services))
      
      (cond [(not maybe-service) (ssh-shutdown sshd 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (format "service '~a' not configured in local machine" service))]
            [else (let ([maybe-identified (userauth-identify sshd username service all-methods)])
                    (cond [(boolean? maybe-identified) maybe-service]
                          [else maybe-identified]))]))))

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
