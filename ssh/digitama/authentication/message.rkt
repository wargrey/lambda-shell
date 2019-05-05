#lang typed/racket/base

(provide (all-defined-out))

(require "../diagnostics.rkt")

(require "../../message.rkt")
(require "../../transport.rkt")
(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-authentication-datum-evt : (-> SSH-Port (Listof Symbol) (Evtof SSH-Datum))
  (lambda [self groups]
    (wrap-evt (ssh-port-read-evt self)
              (λ _ (let ([datum (ssh-port-read self)])
                     (or (and (bytes? datum) (ssh-filter-authentication-message datum groups))
                         datum))))))

(define ssh-write-authentication-message : (-> SSH-Port SSH-Message Void)
  (lambda [self message]
    (ssh-log-outgoing-message message 'debug)

    (ssh-port-send self message)))

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
           (ssh-log-message level "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:userauth:banner? msg)
           (ssh-log-message 'warning "[USER BANNER]~n~a" (ssh:msg:userauth:banner-message msg))])))
