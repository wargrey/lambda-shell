#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4254

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

(struct ssh-connection-service ssh-service
  ([channels : (Mutable-HashTable Index #%Channel)])
  #:type-name SSH-Connection-Service)

(struct #%channel
  ([entity : SSH-Channel]
   [local-id : Index]
   [remote-id : Index]
   [send-window : Index]
   [recv-window : Index]
   [packet-capacity : Index])
  #:type-name #%Channel
  #:mutable)

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
             (define remote-capacity : Index (ssh:msg:channel:open-packet-capacity request))
             (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))

             (define response : SSH-Message
               (cond [(not λchannel) (make-ssh:open:unknown:channel:type remote-id)]
                     [(memq (car λchannel) ($ssh-disabled-channels rfc)) (make-ssh:open:administratively:prohibited remote-id)]
                     [else (with-handlers ([exn:fail:out-of-memory? (λ [[e : exn]] (make-ssh:open:resource:shortage #:source (cdr λchannel) remote-id (exn-message e)))])
                             (define local-id : Index (ssh-channel-eq-uuid request (ssh-connection-service-channels self)))
                             (define maybe-channel : (U SSH-Channel SSH-Message) ((cdr λchannel) type request rfc))
                             (cond [(ssh-message? maybe-channel) maybe-channel]
                                   [else (let ([local-capacity (min ($ssh-payload-capacity rfc) remote-capacity)])
                                           (hash-set! (ssh-connection-service-channels self) local-id
                                                      (#%channel maybe-channel local-id remote-id window-size window-size local-capacity))
                                           (make-ssh:msg:channel:open:confirmation #:recipient remote-id #:sender local-id
                                                                                   #:window-size window-size #:packet-capacity local-capacity))]))]))
             (values self response)]

            [(ssh:msg:channel:request? request)
             (values self #false)]
            
            [else (values self #false)]))))
