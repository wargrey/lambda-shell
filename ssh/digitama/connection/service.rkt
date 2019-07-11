#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require "message.rkt")
(require "channel.rkt")

(require "../message.rkt")
(require "../service.rkt")
(require "../assignment.rkt")

(require "../message/channel.rkt")
(require "../message/connection.rkt")
(require "../assignment/message.rkt")

(require "../../datatype.rkt")
(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [user session rfc]
    (make-ssh-service #:name 'ssh-connection #:user user #:session session #:preference rfc
                      #:range ssh-connection-range #:log-outgoing ssh-log-outgoing-message
                      #:response ssh-connection-response)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest rfc]
    (define request : (Option SSH-Message) (ssh-filter-connection-message brequest))

    (cond [(ssh:msg:channel:open? request)
           (define type : Symbol (ssh:msg:channel:open-type request))
           (define sender : Index (ssh:msg:channel:open-sender request))
           (define window-size : Index (ssh:msg:channel:open-window-size request))
           (define packet-upsize : Index (ssh:msg:channel:open-packet-upsize request))
           (define maybe-channel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))

           (cond [(not maybe-channel) (values self (make-ssh:open:unknown:channel:type sender))]
                 [(memq (car maybe-channel) ($ssh-disabled-channels rfc)) (values self (make-ssh:open:administratively:prohibited sender))]
                 [else (let ([channel ((cdr maybe-channel) type sender window-size packet-upsize request rfc)])
                         (cond [(ssh-message? channel) (values self channel)]
                               [else (values self (make-ssh:msg:channel:open:confirmation #:recipient sender #:sender (ssh-channel-local-id channel)
                                                                                          #:window-size window-size #:packet-upsize packet-upsize))]))])]
          
          [else (values self #false)])))
