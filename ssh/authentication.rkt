#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out) SSH-Maybe-User)

(require racket/port)

(require "digitama/authentication.rkt")
(require "digitama/authentication/message.rkt")
(require "digitama/message/authentication.rkt")

(require "datatype.rkt")
(require "transport.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;; register builtin assignments for authentication methods
(require "digitama/assignment/authentication.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-identify : (-> SSH-Port Symbol
                                [#:service Symbol] [#:services (SSH-Name-Listof* SSH-Service#)] [#:methods (SSH-Name-Listof* SSH-Authentication#)]
                                (U SSH-EOF SSH-Service#))
  (lambda [sshc username #:service [service 'ssh-connection] #:services [services (ssh-registered-services)] #:methods [all-methods (ssh-authentication-methods)]]
    (ssh-write-authentication-message sshc (make-ssh:msg:userauth:request #:username username #:service service #:method 'none))
    
    (let identify ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc #false)])
      (define datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (identify (ssh-authentication-datum-evt sshc #false))]))))

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
