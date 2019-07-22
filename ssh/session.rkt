#lang typed/racket/base

(provide (all-defined-out) SSH-Session)
(provide ssh-session? make-ssh-session)

(require "transport.rkt")
(require "authentication.rkt")

(require "datatype.rkt")
(require "assignment.rkt")

(require "digitama/session.rkt")
(require "digitama/service.rkt")
(require "digitama/diagnostics.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-login : (->* (SSH-Port Symbol)
                              (Symbol #:applications (SSH-Name-Listof* SSH-Application#) #:authentications (SSH-Name-Listof* SSH-Authentication#))
                              (Values (Option SSH-Session) (Option SSH-Application)))
  (lambda [sshd username [service 'ssh-connection] #:applications [applications (ssh-registered-applications)] #:authentications [methods (ssh-authentication-methods)]]
    (parameterize ([current-peer-name (ssh-port-peer-name sshd)]
                   [current-custodian (ssh-custodian sshd)])
      (define maybe-application : SSH-Maybe-Application (ssh-user-identify sshd username service #:applications applications #:methods methods))

      (cond [(not (pair? maybe-application)) (values #false #false)]
            [else (let ([user-session (make-ssh-session sshd maybe-application)])
                    (values user-session
                            (sync/enable-break (ssh-session-service-ready-evt user-session))))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-datum-evt : (All (a) (-> SSH-Session (Evtof a)))
  (lambda [self]
    ((inst ssh-stdin-evt a) (ssh-session-appin self))))

(define ssh-session-read : (-> SSH-Session Any)
  (lambda [self]
    (sync/enable-break (ssh-session-datum-evt self))))

(define ssh-session-write : (-> SSH-Session Any Void)
  (lambda [self datum]
    (thread-send (ssh-session-ghostcat self) datum)))

(define ssh-session-request-service : (-> SSH-Session Symbol [#:wait? Boolean] Void)
  (lambda [self service #:wait? [wait? #true]]
    (ssh-session-write self (make-ssh:msg:service:request #:name service))

    (unless (not wait?)
      (sync/enable-break (ssh-session-service-ready-evt self))
      (void))))

(define ssh-session-service-ready-evt : (-> SSH-Session (Evtof SSH-Application))
  (lambda [self]
    ((inst ssh-stdin-evt SSH-Application) (ssh-session-srvin self))))

(define ssh-session-debug : (->* (SSH-Session Any) (Boolean) Void)
  (lambda [self payload [display? #false]]
    (ssh-port-debug (ssh-session-port self) payload display?)))

(define ssh-session-ignore : (-> SSH-Session Any Void)
  (lambda [self garbage]
    (ssh-port-ignore (ssh-session-port self) garbage)))

(define ssh-session-wait : (-> SSH-Session Void)
  (lambda [self]
    (define ghostcat : Thread (ssh-session-ghostcat self))

    (with-handlers ([exn:break? void])
      (thread-wait ghostcat))

    (unless (thread-dead? ghostcat)
      (break-thread ghostcat)
      (thread-wait ghostcat))))

(define ssh-session-close : (->* (SSH-Session) ((Option String)) Void)
  (lambda [self [description #false]]
    (unless (thread-dead? (ssh-session-ghostcat self))
      (if (not description)
          (ssh-shutdown (ssh-session-port self))
          (ssh-shutdown (ssh-session-port self) description))
      
      (ssh-session-wait self))))
