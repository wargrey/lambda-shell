#lang typed/racket/base

(provide (all-defined-out))

(require "userauth.rkt")

(require "authentication/datatype.rkt")
(require "authentication/message.rkt")

(require "../datatype.rkt")
(require "../message.rkt")
(require "../transport.rkt")
(require "../assignment.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-authenticate : (-> SSH-Port (Listof Symbol) (SSH-Algorithm-Listof* SSH-Authentication#) Index (U SSH-EOF SSH-User Void))
  (lambda [sshc services all-methods limit]
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc #false)]
                       [methods : (SSH-Algorithm-Listof* SSH-Authentication#) all-methods]
                       [auth-self : (Option SSH-Userauth) #false]
                       [retry : Fixnum limit])
      (define datum : SSH-Datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [(null? methods) (ssh-shutdown sshc 'SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE)]
            [(< retry 0) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT "too many authentication failures")]
            [(not (ssh:msg:userauth:request? datum)) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT)]
            [else (let* ([username (ssh:msg:userauth:request-username datum)]
                         [service (ssh:msg:userauth:request-service datum)]
                         [method (ssh:msg:userauth:request-method datum)]
                         [maybe-method (assq method methods)])
                    (define result : (U False Void SSH-Userauth-Option SSH-Userauth)
                      (cond [(not (memq service services)) (ssh-port-reject-service sshc service)]
                            [(not maybe-method) (ssh-write-auth-failure sshc methods)]
                            [else (let* ([auth (userauth-choose-process method (ssh-port-session-identity sshc) (cdr maybe-method) auth-self)]
                                         [response (with-handlers ([exn? (λ [[e : exn]] e)]) ((ssh-userauth-response auth) auth datum username service))])
                                    (cond [(eq? response #false) (ssh-write-auth-failure sshc methods)]
                                          [(ssh:msg:userauth:failure? response) (ssh-write-auth-failure sshc methods response) auth]
                                          [(eq? response #true) (ssh-write-auth-success sshc username #false #true) (make-ssh-userauth-option)]
                                          [(ssh:msg:userauth:success? response) (ssh-write-auth-success sshc username #false response) (make-ssh-userauth-option)]
                                          [(ssh-userauth-option? response) (ssh-write-auth-success sshc username #false #true) response]
                                          [(ssh-message? response) (ssh-write-authentication-message sshc response) auth]
                                          [else (ssh-shutdown sshc 'SSH-DISCONNECT-RESERVED (exn-message response))]))]))
                    (define retry-- : Fixnum (if (or result (= limit 0)) retry (- retry 1)))
                    (cond [(ssh-userauth-option? result) (make-ssh-user username service result)]
                          [(not (void? result))(authenticate (ssh-authentication-datum-evt sshc result) methods result retry--)]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-choose-process : (-> Symbol Bytes SSH-Userauth-Constructor (Option SSH-Userauth) SSH-Userauth)
  (lambda [method-name session-id make-userauth previous]
    (cond [(not previous) (make-userauth session-id)]
          [(eq? method-name (ssh-userauth-name previous)) previous]
          [else (let ([abort (ssh-userauth-abort previous)])
                  (and abort (abort previous))
                  (make-userauth session-id))])))
