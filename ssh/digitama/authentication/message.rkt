#lang typed/racket/base

(provide (all-defined-out))

(require "../userauth.rkt")
(require "../message.rkt")
(require "../assignment.rkt")
(require "../diagnostics.rkt")

(require "../assignment/message.rkt")
(require "../message/authentication.rkt")

(require "../../datatype.rkt")
(require "../../transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-authentication-datum-evt : (-> SSH-Port (Option SSH-Userauth) (Evtof SSH-Datum))
  (lambda [self auth-self]
    (define group : (Option Symbol) (and auth-self (ssh-userauth-name auth-self)))
    
    (wrap-evt (ssh-port-datum-evt self)
              (λ [[datum : SSH-Datum]]
                (or (and (bytes? datum)
                         (ssh-filter-authentication-message datum group))
                    datum)))))

(define ssh-write-authentication-message : (-> SSH-Port SSH-Message Void)
  (lambda [self message]
    (ssh-log-outgoing-message message)

    (ssh-port-write self message)))

(define ssh-write-auth-failure : (case-> [SSH-Port (SSH-Name-Listof* SSH-Authentication#) -> False]
                                         [SSH-Port (SSH-Name-Listof* SSH-Authentication#) SSH-MSG-USERAUTH-FAILURE -> Boolean])
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
    
    (ssh-log-message 'info #:with-peer-name? #false "client[~a@~a] is identified" username (current-peer-name))
    
    (ssh-write-authentication-message self
                                      (cond [(ssh-message? maybe-msg:success) maybe-msg:success]
                                            [else SSH:USERAUTH:SUCCESS]))

    #true))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-filter-authentication-message : (-> Bytes (Option Symbol) (Option SSH-Message))
  (lambda [payload group]
    (define-values (maybe-userauth-msg _) (ssh-bytes->authentication-message payload 0 #:group group))
    
    (unless (not maybe-userauth-msg)
      (ssh-log-message 'debug "found authentication layer message ~a[~a]"
                       (ssh-message-name maybe-userauth-msg)
                       (ssh-message-number maybe-userauth-msg))
      
      (ssh-log-incoming-message maybe-userauth-msg))
    
    maybe-userauth-msg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-outgoing-message : (-> SSH-Message Void)
  (lambda [msg]
    (cond [(ssh:msg:userauth:failure? msg)
           (if (ssh:msg:userauth:failure-partial-success? msg)
               (ssh-log-message 'debug "partially accepted, continue")
               (ssh-log-message 'debug "denied, methods that can continue: ~a"
                                (ssh-names->namelist (ssh:msg:userauth:failure-methods msg))))]
          [(ssh:msg:userauth:banner? msg)
           (ssh-log-message 'debug #:with-peer-name? #false "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))]
          [(ssh:msg:userauth:request? msg)
           (ssh-log-message 'debug "identify '~a' for service '~a' with method '~a'"
                            (ssh:msg:userauth:request-username msg) (ssh:msg:userauth:request-service msg) (ssh:msg:userauth:request-method msg))])))

(define ssh-log-incoming-message : (-> SSH-Message Void)
  (lambda [msg]
    (cond [(ssh:msg:userauth:banner? msg)
           (ssh-log-message #:with-peer-name? #false 'warning "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))]
          [(ssh:msg:userauth:request? msg)
           (ssh-log-message 'debug "'~a' requests the authentication for service '~a' with method '~a'"
                            (ssh:msg:userauth:request-username msg) (ssh:msg:userauth:request-service msg) (ssh:msg:userauth:request-method msg))]
          [(ssh:msg:userauth:failure? msg)
           (if (ssh:msg:userauth:failure-partial-success? msg)
               (ssh-log-message 'debug "needs more information, continue")
               (ssh-log-message 'debug "refused, methods available to retrials: ~a"
                                (ssh-names->namelist (ssh:msg:userauth:failure-methods msg))))])))
