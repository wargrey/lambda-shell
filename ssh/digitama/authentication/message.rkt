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
    (cond [(ssh:msg:debug? msg)
           (when (ssh:msg:debug-display? msg)
             (ssh-log-message level "[DEBUG] ~a" (ssh:msg:debug-message msg)))]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message level "terminate the connection because of ~a, details: ~a"
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message level "cannot not deal with message" (ssh:msg:unimplemented-number msg))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:debug? msg)
           (when (ssh:msg:debug-display? msg)
             (ssh-log-message level "[DEBUG] ~a says: ~a" (current-peer-name) (ssh:msg:debug-message msg)))]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message level "~a has disconnected with the reason ~a(~a)" (current-peer-name)
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message level "~a cannot deal with message ~a" (current-peer-name)
                            (ssh:msg:unimplemented-number msg))])))
