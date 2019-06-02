#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))
(provide SSH-User-Authentication<%>)

(require typed/racket/class)

(require "digitama/userauth.rkt")
(require "digitama/authentication/message.rkt")
(require "digitama/diagnostics.rkt")

(require "datatype.rkt")
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
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshd #false)])
      (define datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (authenticate (ssh-authentication-datum-evt sshd #false))]))))

(define ssh-user-authenticate : (-> SSH-Port (Listof Symbol) [#:methods (SSH-Algorithm-Listof* SSH-Authentication)] (U SSH-EOF SSH-User Void))
  (lambda [sshc services #:methods [all-methods (ssh-authentication-methods)]]
    #;(when (and (string? banner) (> (string-length banner) 0))
      (ssh-write-authentication-message sshc (make-ssh:msg:userauth:banner #:message banner)))
    
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc #false)]
                       [methods : (SSH-Algorithm-Listof* SSH-Authentication) all-methods]
                       [auth-process% : (Option (Instance SSH-User-Authentication<%>)) #false])
      (define datum : SSH-Datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [(null? methods) (ssh-shutdown sshc 'SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE)]
            [(not (ssh:msg:userauth:request? datum)) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT)]
            [else (let* ([username (ssh:msg:userauth:request-username datum)]
                         [service (ssh:msg:userauth:request-service datum)]
                         [method (ssh:msg:userauth:request-method datum)]
                         [maybe-method (assq method methods)])
                    (define result : (U Void Boolean (Instance SSH-User-Authentication<%>))
                      (cond [(not (memq service services)) (ssh-port-reject-service sshc service)]
                            [(not maybe-method) (ssh-write-auth-failure sshc methods #false)]
                            [else (let* ([auth% (userauth-choose-process method (ssh-port-session-identity sshc) (cdr maybe-method) auth-process%)]
                                         [response (send auth% response datum)])
                                    (cond [(or (eq? response #true) (ssh:msg:userauth:success? response)) (ssh-write-auth-success sshc #false response)]
                                          [(or (eq? response #false) (ssh:msg:userauth:failure? response)) (and (ssh-write-auth-failure sshc methods response) auth%)]
                                          [(ssh-message? response) (ssh-write-authentication-message sshc response) auth%]))]))
                    (cond [(eq? result #true) (ssh-user username service)]
                          [(void? result) (authenticate (ssh-authentication-datum-evt sshc auth-process%) methods auth-process%)]
                          [else (authenticate (ssh-authentication-datum-evt sshc result) methods result)]))]))))
