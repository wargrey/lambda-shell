#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "../message.rkt")
(require "../diagnostics.rkt")

(require "../assignment/message.rkt")
(require "../message/connection.rkt")

(define ssh-filter-connection-message : (-> Bytes (Option SSH-Message))
  (lambda [payload]
    (define-values (maybe-connection-msg _) (ssh-bytes->connection-message payload 0))
                                   
    (unless (not maybe-connection-msg)
      (ssh-log-message 'debug "found connection layer message ~a[~a]"
                       (ssh-message-name maybe-connection-msg)
                       (ssh-message-number maybe-connection-msg))
      
      (ssh-log-incoming-message maybe-connection-msg 'debug))
    
    maybe-connection-msg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-outgoing-message : (-> SSH-Message Void)
  (lambda [msg]
    (cond [(ssh:msg:channel:open? msg)
           (ssh-log-message 'debug "request a ~a-window-sized '~a' as channel[0x~a] with maximum packet size ~a"
                            (~size (ssh:msg:channel:open-window-size msg) #:precision 3)
                            (ssh:msg:channel:open-type msg)
                            (number->string (ssh:msg:channel:open-sender msg) 16)
                            (~size (ssh:msg:channel:open-packet-upsize msg) #:precision 3))]
          [(ssh:msg:channel:request? msg)
           (ssh-log-message 'debug "request channel[0x~a] for extension '~a'"
                            (number->string (ssh:msg:channel:request-recipient msg) 16)
                            (ssh:msg:channel:request-type msg))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message 'debug "identify the channel[0x~a] with channel[0x~a]"
                            (number->string (ssh:msg:channel:open:confirmation-recipient msg) 16)
                            (number->string (ssh:msg:channel:open:confirmation-sender msg) 16))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:channel:open? msg)
           (ssh-log-message 'debug "request for opening a ~a-window-sized '~a' as channel[~a] with maximum packet size ~a"
                            (~size (ssh:msg:channel:open-window-size msg) #:precision 3)
                            (ssh:msg:channel:open-type msg)
                            (number->string (ssh:msg:channel:open-sender msg) 16)
                            (~size (ssh:msg:channel:open-packet-upsize msg) #:precision 3))]
          [(ssh:msg:channel:request? msg)
           (ssh-log-message 'debug "request channel[0x~a] for extension '~a'"
                            (number->string (ssh:msg:channel:request-recipient msg) 16)
                            (ssh:msg:channel:request-type msg))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message 'debug "the channel[0x~a] has been identified with channel[0x~a]"
                            (number->string (ssh:msg:channel:open:confirmation-sender msg) 16)
                            (number->string (ssh:msg:channel:open:confirmation-recipient msg) 16))])))
