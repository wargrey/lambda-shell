#lang typed/racket/base

(provide (all-defined-out))

(require "../userauth.rkt")
(require "../diagnostics.rkt")

(require "../../assignment.rkt")
(require "../../message.rkt")
(require "../../datatype.rkt")
(require "../../transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-authentication-datum-evt : (-> SSH-Port (Option SSH-Userauth) (Evtof SSH-Datum))
  (lambda [self auth-self]
    (define groups : (Listof Symbol)
      (cond [(not auth-self) null]
            [else (list (ssh-userauth-name auth-self))]))
    
    (wrap-evt (ssh-port-read-evt self)
              (λ _ (let ([datum (ssh-port-read self)])
                     (or (and (bytes? datum) (ssh-filter-authentication-message datum groups))
                         datum))))))

(define ssh-write-authentication-message : (-> SSH-Port SSH-Message Void)
  (lambda [self message]
    (ssh-log-outgoing-message message 'debug)

    (ssh-port-send self message)))

(define ssh-write-auth-failure : (case-> [SSH-Port (SSH-Algorithm-Listof* SSH-Authentication#) -> False]
                                         [SSH-Port (SSH-Algorithm-Listof* SSH-Authentication#) SSH-MSG-USERAUTH-FAILURE -> Boolean])
  (case-lambda
    [(self methods)
     (ssh-write-authentication-message self (make-ssh:msg:userauth:failure #:methods methods #:partial-success? #false))
     #false]
    [(self methods msg:failure)
     (let ([okay? (ssh:msg:userauth:failure-partial-success? msg:failure)])
       (ssh-write-authentication-message self (make-ssh:msg:userauth:failure #:methods methods #:partial-success? okay?))
       okay?)]))

(define ssh-write-auth-success : (-> SSH-Port Symbol (Option String) (U SSH-MSG-USERAUTH-SUCCESS True) True)
  (lambda [self username banner maybe-msg:success]
    #;(when (and (string? banner) (> (string-length banner) 0))
        (ssh-write-authentication-message sshc (make-ssh:msg:userauth:banner #:message banner)))
    
    (ssh-log-message 'debug #:with-peer-name? #false "accept client[~a@~a]" username (current-peer-name))
    
    (ssh-write-authentication-message self
                                      (cond [(ssh-message? maybe-msg:success) maybe-msg:success]
                                            [else (make-ssh:msg:userauth:success)]))

    #true))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-filter-authentication-message : (-> Bytes (Listof Symbol) (Option SSH-Message))
  (lambda [payload groups]
    (define-values (maybe-userauth-msg _) (ssh-bytes->authentication-message payload 0 #:groups groups))
                                   
    (unless (not maybe-userauth-msg)
      (ssh-log-message 'debug "found authentication message ~a[~a]"
                       (ssh-message-name maybe-userauth-msg)
                       (ssh-message-number maybe-userauth-msg))
      
      (ssh-log-incoming-message maybe-userauth-msg 'debug))
    
    maybe-userauth-msg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-outgoing-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:userauth:failure? msg)
           (if (ssh:msg:userauth:failure-partial-success? msg)
               (ssh-log-message level "partially accepted, continue")
               (ssh-log-message level "denied, methods that can continue: ~a"
                                (ssh-algorithms->names (ssh:msg:userauth:failure-methods msg))))]
          [(ssh:msg:userauth:banner? msg)
           (ssh-log-message level #:with-peer-name? #false "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:userauth:banner? msg)
           (ssh-log-message #:with-peer-name? #false 'warning "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))]
          [(ssh:msg:userauth:request? msg)
           (ssh-log-message level "'~a' requests authentication with method '~a'"
                            (ssh:msg:userauth:request-username msg) (ssh:msg:userauth:request-method msg))])))
