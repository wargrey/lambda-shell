#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "transport.rkt")
(require "authentication.rkt")

(require "datatype.rkt")
(require "assignment.rkt")

(require "digitama/daemon.rkt")
(require "digitama/diagnostics.rkt")

(require "digitama/authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-daemon : (-> SSH-Listener [#:services (SSH-Name-Listof* SSH-Service#)] [#:authentications (SSH-Name-Listof* SSH-Authentication#)] Void)
  (lambda [sshd #:services [services (ssh-registered-services)] #:authentications [methods (ssh-authentication-methods)]]
    (ssh-daemon-accept sshd (λ [[sshc : SSH-Port]] (ssh-daemon-serve sshc #:services services #:authentications methods)))))

(define ssh-daemon/no-authentication : (-> SSH-Listener [#:services (SSH-Name-Listof* SSH-Service#)] Void)
  (lambda [sshd #:services [services (ssh-registered-services)]]
    (ssh-daemon-accept sshd (λ [[sshc : SSH-Port]] (ssh-daemon-serve/no-authentication sshc #:services services)))))

(define ssh-daemon/authenticate : (-> SSH-Listener (-> (SSH-Name-Listof* SSH-Service#) SSH-Maybe-User) [#:services (SSH-Name-Listof* SSH-Service#)] Void)
  (lambda [sshd authenticate #:services [services (ssh-registered-services)]]
    (ssh-daemon-accept sshd (λ [[sshc : SSH-Port]] (ssh-daemon-serve/authenticate sshc authenticate #:services services)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-daemon-serve : (-> SSH-Port [#:services (SSH-Name-Listof* SSH-Service#)] [#:authentications (SSH-Name-Listof* SSH-Authentication#)] Void)
  (lambda [sshd #:services [services (ssh-registered-services)] #:authentications [methods (ssh-authentication-methods)]]
    (ssh-daemon-serve/authenticate sshd #:services services
                                   (λ [[s : (SSH-Name-Listof* SSH-Service#)]]
                                     (ssh-user-authenticate sshd #:services s)))))

(define ssh-daemon-serve/no-authentication : (-> SSH-Port [#:services (SSH-Name-Listof* SSH-Service#)] Void)
  (lambda [sshd #:services [services (ssh-registered-services)]]
    (ssh-daemon-serve/authenticate sshd #:services services
                                   (λ [[s : (SSH-Name-Listof* SSH-Service#)]]
                                     (ssh-user-authenticate/none sshd #:services s)))))

(define ssh-daemon-serve/authenticate : (-> SSH-Port (-> (SSH-Name-Listof* SSH-Service#) SSH-Maybe-User) [#:services (SSH-Name-Listof* SSH-Service#)] Void)
  (lambda [sshd authenticate #:services [services (ssh-registered-services)]]
    (parameterize ([current-peer-name (ssh-port-peer-name sshd)])
      (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
        (define maybe-user : SSH-Maybe-User (authenticate services))
        
        (when (pair? maybe-user)
          (ssh-daemon-dispatch sshd (car maybe-user) (cdr maybe-user) services))))))
