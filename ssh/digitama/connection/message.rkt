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
    (cond [(ssh:msg:channel:data? msg)
           (ssh-log-message 'debug "sent ~a data to channel[0x~a]"
                            (~size (bytes-length (ssh:msg:channel:data-payload msg)) #:precision 3)
                            (number->string (ssh:msg:channel:data-recipient msg) 16))]
          [(ssh:msg:channel:extended:data? msg)
           (ssh-log-message 'debug "sent ~a extended data to channel[0x~a]"
                            (~size (bytes-length (ssh:msg:channel:extended:data-payload msg)) #:precision 3)
                            (number->string (ssh:msg:channel:extended:data-recipient msg) 16))]
          [(ssh:msg:channel:window:adjust? msg)
           (ssh-log-message 'debug "adjust the incoming window sized by ~a for channel[0x~a]"
                            (~size (ssh:msg:channel:window:adjust-increment msg) #:precision 3)
                            (number->string (ssh:msg:channel:window:adjust-recipient msg) 16))]
          [(ssh:msg:channel:open? msg)
           (ssh-log-message 'debug "open a ~a-window-sized '~a' as channel[0x~a] with packet capacity ~a"
                            (~size (ssh:msg:channel:open-window-size msg) #:precision 3)
                            (ssh:msg:channel:open-type msg)
                            (number->string (ssh:msg:channel:open-sender msg) 16)
                            (~size (ssh:msg:channel:open-packet-capacity msg) #:precision 3))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message 'debug "identify the channel[0x~a] with channel[0x~a], employing a ~a-sized packet"
                            (number->string (ssh:msg:channel:open:confirmation-recipient msg) 16)
                            (number->string (ssh:msg:channel:open:confirmation-sender msg) 16)
                            (~size (ssh:msg:channel:open:confirmation-packet-capacity msg) #:precision 3))]
          [(ssh:msg:channel:request? msg)
           (ssh-log-message 'debug "request the extension '~a' of channel[0x~a] (~a reply)"
                            (ssh:msg:channel:request-type msg)
                            (number->string (ssh:msg:channel:request-recipient msg) 16)
                            (if (ssh:msg:channel:request-reply? msg) 'wants 'no))]
          [(ssh:msg:channel:eof? msg)
           (ssh-log-message 'debug "notify channel[0x~a] that no more data to be sent" (ssh:msg:channel:eof-recipient msg))]
          [(ssh:msg:channel:close? msg)
           (ssh-log-message 'debug "notify channel[0x~a] to close" (ssh:msg:channel:close-recipient msg))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:channel:data? msg)
           (ssh-log-message 'debug "received ~a data for channel[0x~a]"
                            (~size (bytes-length (ssh:msg:channel:data-payload msg)) #:precision 3)
                            (number->string (ssh:msg:channel:data-recipient msg) 16))]
          [(ssh:msg:channel:extended:data? msg)
           (ssh-log-message 'debug "received ~a extended data for channel[0x~a]"
                            (~size (bytes-length (ssh:msg:channel:extended:data-payload msg)) #:precision 3)
                            (number->string (ssh:msg:channel:extended:data-recipient msg) 16))]
          [(ssh:msg:channel:window:adjust? msg)
           (ssh-log-message 'debug "the outgoing window size of channel[0x~a] has increamented by ~a"
                            (number->string (ssh:msg:channel:window:adjust-recipient msg) 16)
                            (~size (ssh:msg:channel:window:adjust-increment msg) #:precision 3))]
          [(ssh:msg:channel:open? msg)
           (ssh-log-message 'debug "try opening a ~a-window-sized '~a' as channel[0x~a] with packet capacity ~a"
                            (~size (ssh:msg:channel:open-window-size msg) #:precision 3)
                            (ssh:msg:channel:open-type msg)
                            (number->string (ssh:msg:channel:open-sender msg) 16)
                            (~size (ssh:msg:channel:open-packet-capacity msg) #:precision 3))]
          [(ssh:msg:channel:open:confirmation? msg)
           (ssh-log-message 'debug "the channel[0x~a] has been identified with channel[0x~a] over a ~a-sized packet"
                            (number->string (ssh:msg:channel:open:confirmation-sender msg) 16)
                            (number->string (ssh:msg:channel:open:confirmation-recipient msg) 16)
                            (~size (ssh:msg:channel:open:confirmation-packet-capacity msg) #:precision 3))]
          [(ssh:msg:channel:request? msg)
           (ssh-log-message 'debug "request channel[0x~a] for the extension '~a' (~a reply)"
                            (number->string (ssh:msg:channel:request-recipient msg) 16)
                            (ssh:msg:channel:request-type msg)
                            (if (ssh:msg:channel:request-reply? msg) 'wants 'no))]
          [(ssh:msg:channel:eof? msg)
           (ssh-log-message 'debug "half close the channel[0x~a]" (ssh:msg:channel:eof-recipient msg))]
          [(ssh:msg:channel:close? msg)
           (ssh-log-message 'debug "close the channel[0x~a]" (ssh:msg:channel:close-recipient msg))])))
