#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out) SSH-Maybe-User SSH-Maybe-Application)

(require racket/port)

(require "digitama/authentication.rkt")
(require "digitama/transport.rkt")

(require "datatype.rkt")
(require "transport.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;; register builtin assignments for authentication methods
(require "digitama/assignment/authentication.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-identify : (->* (SSH-Port Symbol)
                                 (Symbol #:applications (SSH-Name-Listof* SSH-Application#) #:methods (SSH-Name-Listof* SSH-Authentication#))
                                 SSH-Maybe-Application)
  (lambda [sshd username [service 'ssh-connection] #:applications [applications (ssh-registered-applications)] #:methods [all-methods (ssh-authentication-methods)]]
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (exn-message e)))])
      (define maybe-application : (Option (SSH-Nameof SSH-Application#)) (assq service applications))
      
      (cond [(not maybe-application) (ssh-shutdown sshd 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (ssh-service-not-configured-description service))]
            [else (let ([maybe-identified (userauth-identify sshd username service all-methods)])
                    (cond [(boolean? maybe-identified) maybe-application]
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
