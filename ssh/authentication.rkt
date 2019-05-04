#lang typed/racket/base

(provide (all-defined-out))

(require "digitama/diagnostics.rkt")
(require "digitama/authentication/message.rkt")

(require "transport.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;; register builtin assignments for authentication methods
(require "digitama/assignment/authentication.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-user
  ([name : Symbol]
   [service : Symbol])
  #:transparent
  #:type-name SSH-User)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-request : (->* (SSH-Port Symbol) (Symbol) (U SSH-EOF True))
  (lambda [sshd username [service 'ssh-connection]]
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshd null)])
      (define datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (authenticate (ssh-authentication-datum-evt sshd null))]))))

(define ssh-user-authenticate : (-> SSH-Port (Listof Symbol) (U SSH-EOF SSH-User))
  (lambda [sshc services]
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc null)])
      (define datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (authenticate (ssh-authentication-datum-evt sshc null))]))))
