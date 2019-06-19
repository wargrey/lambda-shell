#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))
(provide SSH-User-Authentication<%>)
(provide (all-from-out "digitama/authentication/option.rkt"))

(require racket/port)

(require typed/racket/class)

(require "digitama/userauth.rkt")
(require "digitama/diagnostics.rkt")

(require "digitama/authentication/option.rkt")
(require "digitama/authentication/message.rkt")

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
   [service : Symbol]
   [options : SSH-Userauth-Option])
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
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define timeout : Index ($ssh-userauth-timeout rfc))
    (define limit : Index ($ssh-userauth-retry rfc))
    
    (define (authenticate) : (U SSH-EOF SSH-User Void)
      (let authenticate ([datum-evt : (Evtof SSH-Datum) (ssh-authentication-datum-evt sshc #false)]
                         [methods : (SSH-Algorithm-Listof* SSH-Authentication) all-methods]
                         [auth% : (Option (Instance SSH-User-Authentication<%>)) #false]
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
                      (define result : (U Void Boolean (Instance SSH-User-Authentication<%>))
                        (cond [(not (memq service services)) (ssh-port-reject-service sshc service)]
                              [(not maybe-method) (ssh-write-auth-failure sshc methods #false)]
                              [else (let* ([auth% (userauth-choose-process method (ssh-port-session-identity sshc) (cdr maybe-method) auth%)]
                                           [response (send auth% response datum username service)])
                                      (cond [(or (eq? response #true) (ssh:msg:userauth:success? response)) (ssh-write-auth-success sshc #false response)]
                                            [(or (eq? response #false) (ssh:msg:userauth:failure? response)) (and (ssh-write-auth-failure sshc methods response) auth%)]
                                            [else (ssh-write-authentication-message sshc response) auth%]))]))
                      (define retry-- : Fixnum (if (or result (= limit 0)) retry (- retry 1)))
                      (cond [(eq? result #true) (ssh-user username service (or (and auth% (send auth% userauth-option username)) (make-ssh-userauth-option)))]
                            [(void? result) (authenticate (ssh-authentication-datum-evt sshc auth%) methods auth% retry--)]
                            [else (authenticate (ssh-authentication-datum-evt sshc result) methods result retry--)]))])))

    (cond [(= timeout 0) (authenticate)]
          [else (parameterize ([current-custodian (make-custodian)])
                  (let-values ([(/dev/stdin /dev/stdout) (make-pipe-with-specials)])
                  (define ghostcat : Thread (thread (λ [] (write-special (with-syntax ([exn? values]) (authenticate)) /dev/stdout))))
                  
                  (let ([datum (sync/timeout/enable-break timeout (wrap-evt /dev/stdin (λ _ (read-byte-or-special /dev/stdin))))])
                    (custodian-shutdown-all (current-custodian))
                    (thread-wait ghostcat)
                    
                    (cond [(or (ssh-user? datum) (ssh-eof? datum) (void? datum)) datum]
                          [else (ssh-shutdown sshc 'SSH-DISCONNECT-HOST-NOT-ALLOWED-TO-CONNECT "authentication timeout")]))))])))
  