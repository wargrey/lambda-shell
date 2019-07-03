#lang typed/racket/base

(provide (all-defined-out))

(require "../diagnostics.rkt")

(require "../message/connection.rkt")

(require "../../message.rkt")
(require "../../transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-datum-evt : (-> SSH-Port (Evtof SSH-Datum))
  (lambda [self] 
    (wrap-evt (ssh-port-read-evt self)
              (λ _ (let ([datum (ssh-port-read self)])
                     (or (and (bytes? datum) (ssh-filter-connection-message datum))
                         datum))))))

(define ssh-write-connection-message : (-> SSH-Port SSH-Message Void)
  (lambda [self message]
    (ssh-log-outgoing-message message 'debug)

    (ssh-port-write self message)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-filter-connection-message : (-> Bytes (Option SSH-Message))
  (lambda [payload]
    (define-values (maybe-connection-msg _) (ssh-bytes->connection-message payload 0))
                                   
    (unless (not maybe-connection-msg)
      (ssh-log-message 'debug "found connection message ~a[~a]"
                       (ssh-message-name maybe-connection-msg)
                       (ssh-message-number maybe-connection-msg))
      
      (ssh-log-incoming-message maybe-connection-msg 'debug))
    
    maybe-connection-msg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-outgoing-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:channel:open? msg)
           (ssh-log-message level "request a ~a-window-sized '~a' as channel[~a]"
                            (ssh:msg:channel:open-window-size msg) (ssh:msg:channel:open-type msg) (ssh:msg:channel:open-sender msg))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message level "identify the channel[~a] with channel[~a]"
                            (ssh:msg:channel:open:confirmation-recipient msg) (ssh:msg:channel:open:confirmation-sender msg))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:channel:open? msg)
           (ssh-log-message level "request for opening a ~a-window-sized '~a' as channel[~a]"
                            (ssh:msg:channel:open-window-size msg) (ssh:msg:channel:open-type msg) (ssh:msg:channel:open-sender msg))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message level "the channel[~a] has been identified with channel[~a]"
                            (ssh:msg:channel:open:confirmation-sender msg) (ssh:msg:channel:open:confirmation-recipient msg))])))
