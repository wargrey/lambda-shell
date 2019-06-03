#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "../userauth.rkt")
(require "../diagnostics.rkt")

(require "../../assignment.rkt")
(require "../../message.rkt")
(require "../../datatype.rkt")
(require "../../transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-authentication-datum-evt : (-> SSH-Port (Option (Instance SSH-User-Authentication<%>)) (Evtof SSH-Datum))
  (lambda [self auth-process%]
    (define groups : (Listof Symbol)
      (cond [(not auth-process%) null]
            [else (list (send auth-process% tell-method-name))]))
    
    (wrap-evt (ssh-port-read-evt self)
              (λ _ (let ([datum (ssh-port-read self)])
                     (or (and (bytes? datum) (ssh-filter-authentication-message datum groups))
                         datum))))))

(define ssh-write-authentication-message : (-> SSH-Port SSH-Message Void)
  (lambda [self message]
    (ssh-log-outgoing-message message 'debug)

    (ssh-port-send self message)))

(define ssh-write-auth-failure : (-> SSH-Port (SSH-Algorithm-Listof* SSH-Authentication) (Option SSH-MSG-USERAUTH-FAILURE) Boolean)
  (lambda [self methods maybe-msg:failure]
    (define okay? : Boolean
      (cond [(not maybe-msg:failure) #false]
            [else (ssh:msg:userauth:failure-partial-success? maybe-msg:failure)]))

    (ssh-write-authentication-message self (make-ssh:msg:userauth:failure #:methods methods #:partial-success? okay?))

    okay?))

(define ssh-write-auth-success : (-> SSH-Port (Option String) (U SSH-MSG-USERAUTH-SUCCESS True) True)
  (lambda [self banner maybe-msg:success]
    #;(when (and (string? banner) (> (string-length banner) 0))
        (ssh-write-authentication-message sshc (make-ssh:msg:userauth:banner #:message banner)))
    
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
    (cond [(ssh:msg:userauth:banner? msg)
           (ssh-log-message level "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))]
          [(ssh:msg:userauth:failure? msg)
           (if (ssh:msg:userauth:failure-partial-success? msg)
               (ssh-log-message level "~a partially accepted, continue" (current-peer-name))
               (ssh-log-message level "~a is denied, methods that can continue: ~a"
                                (current-peer-name) (ssh-algorithms->names (ssh:msg:userauth:failure-methods msg))))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:userauth:banner? msg)
           (ssh-log-message 'warning "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))]
          [(ssh:msg:userauth:request? msg)
           (ssh-log-message level "~a@~a requests authentication with method '~a'"
                            (ssh:msg:userauth:request-username msg) (current-peer-name) (ssh:msg:userauth:request-method msg))])))
