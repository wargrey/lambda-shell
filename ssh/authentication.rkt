#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

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

(define ssh-user-authenticate : (-> SSH-Port (Listof Symbol) (U SSH-EOF SSH-User False))
  (lambda [sshc services]
    #;(when (and (string? banner) (> (string-length banner) 0))
      (ssh-write-authentication-message sshc (make-ssh:msg:userauth:banner #:message banner)))
    
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc null)])
      (define datum : SSH-Datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [(not (ssh:msg:userauth:request? datum)) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT) #false]
            [else (let ([service (ssh:msg:userauth:request-service datum)])
                    (cond [(not (memq service services)) (ssh-port-reject-service sshc service) #false]
                          [else (authenticate (ssh-authentication-datum-evt sshc null))]))]))))
