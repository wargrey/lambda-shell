#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require "message.rkt")
(require "channel.rkt")
(require "channel/uuid.rkt")

(require "../message.rkt")
(require "../service.rkt")
(require "../assignment.rkt")

(require "../message/channel.rkt")
(require "../message/connection.rkt")
(require "../assignment/message.rkt")

(require "../../datatype.rkt")
(require "../../configuration.rkt")

(define-type SSH-Channel-Info (Mutable-Vector SSH-Channel Index Index Index Index))

(struct ssh-connection-service ssh-service
  ([channels : (Mutable-HashTable Index (List Index Index SSH-Channel))])
  #:type-name SSH-Connection-Service)

(define window-upsize : Natural (- (expt 2 32) 1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [user session rfc]
    (ssh-connection-service (super-ssh-service #:name 'ssh-connection #:user user #:session session #:preference rfc
                                               #:range ssh-connection-range #:log-outgoing ssh-log-outgoing-message
                                               #:response ssh-connection-response)
                            (make-hasheq))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest]
    (with-asserts ([self ssh-connection-service?])
      (define request : (Option SSH-Message) (ssh-filter-connection-message brequest))
      
      (cond [(ssh:msg:channel:open? request)
             (define rfc : SSH-Configuration (ssh-service-preference self))
             (define type : Symbol (ssh:msg:channel:open-type request))
             (define remote-id : Index (ssh:msg:channel:open-sender request))
             (define window-size : Index (ssh:msg:channel:open-window-size request)) ; uint32 field, its value is always smaller than the `window-upsize`
             (define packet-capacity : Index (ssh:msg:channel:open-packet-capacity request))
             (define maybe-channel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))
             
             (cond [(not maybe-channel) (values self (make-ssh:open:unknown:channel:type remote-id))]
                   [(memq (car maybe-channel) ($ssh-disabled-channels rfc)) (values self (make-ssh:open:administratively:prohibited remote-id))]
                   [else (let* ([local-id (ssh-channel-eq-uuid request (ssh-connection-service-channels self))]
                                [channel ((cdr maybe-channel) type local-id remote-id window-size packet-capacity request rfc)])
                           (cond [(ssh-message? channel) (values self channel)]
                                 [else (let ([payload-capacity ($ssh-payload-capacity rfc)])
                                         (values self
                                                 (make-ssh:msg:channel:open:confirmation #:recipient remote-id #:sender local-id
                                                                                         #:window-size window-size #:packet-capacity packet-capacity)))]))])]
            
            [else (values self #false)]))))
