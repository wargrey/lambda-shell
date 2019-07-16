#lang typed/racket/base

(provide (all-defined-out))

(require "userauth.rkt")
(require "assignment.rkt")

(require "message/authentication.rkt")
(require "authentication/user.rkt")
(require "authentication/message.rkt")

(require "../datatype.rkt")
(require "../message.rkt")
(require "../transport.rkt")

(define-type SSH-Maybe-User (U SSH-EOF Void (Pairof SSH-User (SSH-Nameof SSH-Service#))))
(define-type SSH-Maybe-Service (U SSH-EOF Void (SSH-Nameof SSH-Service#)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-identify : (-> SSH-Port Symbol Symbol (SSH-Name-Listof* SSH-Authentication#) (U SSH-EOF Void True))
  (lambda [sshd username service all-methods]
    (define (do-request [self : (Option SSH-Userauth)] [response : (U SSH-Message Boolean)] [methods : (SSH-Name-Listof* SSH-Authentication#)]) : (U SSH-EOF Void True)
      (define-values (auth request)
        (ssh-userauth.request (or self ((cdar methods) (caar methods) #false))
                              username service response (ssh-port-session-identity sshd)))
      
      (cond [(ssh-message? request) (ssh-write-authentication-message sshd request) (do-identify auth methods)]
            [else (let ([retry-methods (ssh-names-remove (ssh-userauth-name auth) methods)])
                    (cond [(null? retry-methods) (ssh-shutdown sshd 'SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE)]
                          [else (do-request #false #false retry-methods)]))]))

    (define (do-identify [maybe-auth : (Option SSH-Userauth)] [methods : (SSH-Name-Listof* SSH-Authentication#)]) : (U SSH-EOF Void True)
      (define datum : SSH-Datum (sync/enable-break (ssh-authentication-datum-evt sshd maybe-auth)))
      
      (cond [(ssh-eof? datum) datum]
            [(ssh:msg:userauth:success? datum) (ssh-read-auth-success username service)]
            [(and maybe-auth (ssh-userauth-message? datum)) (do-request maybe-auth datum methods)]
            [(not (ssh:msg:userauth:failure? datum)) (do-identify maybe-auth methods)]
            [else (let ([retry-methods (ssh-names-intersect methods (ssh:msg:userauth:failure-methods datum))]
                        [partial-success? (ssh:msg:userauth:failure-partial-success? datum)])
                    (cond [(null? retry-methods) (ssh-shutdown sshd 'SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE)]
                          [(and maybe-auth (assq (ssh-userauth-name maybe-auth) retry-methods)) (do-request maybe-auth partial-success? retry-methods)]
                          [else (do-request #false #false retry-methods)]))]))

    (ssh-port-request-service sshd 'ssh-userauth)
    (sync/enable-break (ssh-authentication-datum-evt sshd #false))
    
    (ssh-write-authentication-message sshd (make-ssh:msg:userauth:request #:username username #:service service #:method 'none))
    (do-identify #false all-methods)))

(define userauth-authenticate : (-> SSH-Port (SSH-Name-Listof* SSH-Service#) (SSH-Name-Listof* SSH-Authentication#) Index SSH-Maybe-User)
  (lambda [sshc services all-methods limit]
    (let authenticate ([methods : (SSH-Name-Listof* SSH-Authentication#) all-methods]
                       [auth-self : (Option SSH-Userauth) #false]
                       [retry : Fixnum limit])
      (define datum : SSH-Datum (sync/enable-break (ssh-authentication-datum-evt sshc auth-self)))
      
      (cond [(ssh-eof? datum) datum]
            [(null? methods) (ssh-shutdown sshc 'SSH-DISCONNECT-NO-MORE-AUTH-METHODS-AVAILABLE)]
            [(< retry 0) (ssh-shutdown sshc 'SSH-DISCONNECT-TOO-MANY-CONNECTIONS "too many authentication failures")]
            [(not (ssh:msg:userauth:request? datum)) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT)]
            [else (let* ([username (ssh:msg:userauth:request-username datum)]
                         [service (ssh:msg:userauth:request-service datum)]
                         [method (ssh:msg:userauth:request-method datum)]
                         [maybe-λservice (assq service services)]
                         [maybe-λmethod (assq method methods)])
                    (define result : (U False Void SSH-Userauth-Option SSH-Userauth True)
                      (cond [(not maybe-λservice) (ssh-port-reject-service sshc service)]
                            [(not maybe-λmethod) (ssh-write-auth-failure sshc methods)]
                            [else (let* ([auth (userauth-choose-process method (cdr maybe-λmethod) auth-self)]
                                         [response (ssh-userauth.response auth datum username service (ssh-port-session-identity sshc))])
                                    (cond [(eq? response #false) (ssh-write-auth-failure sshc methods)]
                                          [(ssh:msg:userauth:failure? response) (ssh-write-auth-failure sshc methods response) auth]
                                          [(eq? response #true) (ssh-write-auth-success sshc username #false #true)]
                                          [(ssh:msg:userauth:success? response) (ssh-write-auth-success sshc username #false response)]
                                          [(ssh-userauth-option? response) (ssh-write-auth-success sshc username #false #true) response]
                                          [(ssh-message? response) (ssh-write-authentication-message sshc response) auth]))]))
                    (define retry-- : Fixnum (if (or result (= limit 0)) retry (- retry 1)))
                    (cond [(ssh-userauth-option? result) (cons (make-ssh-user username result) (assert maybe-λservice))]
                          [(eq? result #true) (cons (make-ssh-user username #false) (assert maybe-λservice))]
                          [(not (void? result))(authenticate methods result retry--)]))]))))

(define userauth-none : (-> SSH-Port (SSH-Name-Listof* SSH-Service#) Index SSH-Maybe-User)
  (lambda [sshc services limit]
    (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc #false)]
                       [retry : Fixnum limit])
      (define datum : SSH-Datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [(< retry 0) (ssh-shutdown sshc 'SSH-DISCONNECT-TOO-MANY-CONNECTIONS "too many authentication failures")]
            [(not (ssh:msg:userauth:request? datum)) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT)]
            [else (let* ([username (ssh:msg:userauth:request-username datum)]
                         [service (ssh:msg:userauth:request-service datum)]
                         [method (ssh:msg:userauth:request-method datum)]
                         [maybe-service (assq service services)])
                    (define result : (U False Void SSH-Userauth-Option)
                      (cond [(not maybe-service) (ssh-port-reject-service sshc service)]
                            [else (ssh-write-auth-success sshc username #false #true) (make-ssh-userauth-option)]))
                    (define retry-- : Fixnum (if (or result (= limit 0)) retry (- retry 1)))
                    (cond [(ssh-userauth-option? result) (cons (make-ssh-user username result) (assert maybe-service))]
                          [(not (void? result)) (authenticate (ssh-authentication-datum-evt sshc result) retry--)]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-choose-process : (-> Symbol SSH-Userauth-Constructor (Option SSH-Userauth) SSH-Userauth)
  (lambda [method-name make-userauth previous]
    (cond [(and previous (eq? method-name (ssh-userauth-name previous))) previous]
          [else (make-userauth method-name #true)])))

(define userauth-timeout : (All (a) (-> SSH-Port (-> a) Index (U a Void)))
  (lambda [sshc authenticate timeout]
    (cond [(= timeout 0) (authenticate)]
          [else (parameterize ([current-custodian (make-custodian)])
                  (let ([&mailbox : (Boxof (Option a)) (box #false)])
                    (define ghostcat : Thread (thread (λ [] (set-box! &mailbox (authenticate)))))
                  
                    (sync/timeout/enable-break timeout ghostcat)
                    (let ([datum (unbox &mailbox)])
                      (custodian-shutdown-all (current-custodian))
                      (thread-wait ghostcat)
                      
                      (cond [(not datum) (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT "authentication timeout")]
                            [else datum]))))])))
