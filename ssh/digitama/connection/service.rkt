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
   [self : Index]
   [partner : Index]
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
                                               #:response ssh-connection-response #:datum-evt ssh-connection-datum-evt
                                               #:destruct ssh-connection-destruct)
                            (make-hasheq))))

(define ssh-connection-destruct : SSH-Service-Destructor
  (lambda [self]
    (with-asserts ([self ssh-connection-service?])
      (for ([chinfo (in-hash-values (ssh-connection-service-channels self))])
        (ssh-channel.destruct (#%channel-entity chinfo))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest]
    (with-asserts ([self ssh-connection-service?])
      (define request : (Option SSH-Message) (ssh-filter-connection-message brequest))
      
      (cond [(ssh:msg:channel:open? request)
             (define rfc : SSH-Configuration (ssh-service-preference self))
             (define type : Symbol (ssh:msg:channel:open-type request))
             (define partner : Index (ssh:msg:channel:open-sender request))
             (define window-size : Index (ssh:msg:channel:open-window-size request)) ; uint32 field, its value is always smaller than the `window-upsize`
             (define remote-capacity : Index (ssh:msg:channel:open-packet-capacity request))
             (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))

             (define response : SSH-Message
               (cond [(not λchannel) (make-ssh:open:unknown:channel:type partner)]
                     [(memq (car λchannel) ($ssh-disabled-channels rfc)) (make-ssh:open:administratively:prohibited partner)]
                     [else (with-handlers ([exn:fail:out-of-memory? (λ [[e : exn]] (make-ssh:open:resource:shortage #:source (cdr λchannel) partner (exn-message e)))])
                             (define self-id : Index (ssh-channel-eq-uuid request (ssh-connection-service-channels self)))
                             (define maybe-channel : (U SSH-Channel SSH-Message) ((cdr λchannel) type request rfc))
                             (cond [(ssh-message? maybe-channel) maybe-channel]
                                   [else (let ([local-capacity (min ($ssh-payload-capacity rfc) remote-capacity)])
                                           (hash-set! (ssh-connection-service-channels self) self-id
                                                      (#%channel maybe-channel self-id partner window-size window-size local-capacity))
                                           (make-ssh:msg:channel:open:confirmation #:recipient partner #:sender self-id
                                                                                   #:window-size window-size #:packet-capacity local-capacity))]))]))
             (values self response)]

            [(ssh:msg:channel:request? request)
             (define rfc : SSH-Configuration (ssh-service-preference self))
             (define id : Index (ssh:msg:channel:request-recipient request))
             (define reply? : Boolean (ssh:msg:channel:request-reply? request))
             (define maybe-chinfo : (Option #%channel) (hash-ref (ssh-connection-service-channels self) id (λ [] #false)))

             (cond [(not maybe-chinfo) (values self #false)]
                   [else (let ([channel (#%channel-entity maybe-chinfo)]
                               [partner (#%channel-partner maybe-chinfo)])
                           (define-values (channel++ okay?) (ssh-channel.response channel request rfc))
                           (unless (eq? channel channel++)
                             (set-#%channel-entity! maybe-chinfo channel++))
                           (values self
                                   (and reply?
                                        (if (not okay?)
                                            (make-ssh:msg:channel:failure #:recipient partner)
                                            (make-ssh:msg:channel:success #:recipient partner)))))])]

            [(ssh:msg:channel:close? request)
             (define id : Index (ssh:msg:channel:close-recipient request))
             (define maybe-chinfo : (Option #%channel) (hash-ref (ssh-connection-service-channels self) id (λ [] #false)))

             (cond [(not maybe-chinfo) (values self #false)]
                   [else (let ([channel (#%channel-entity maybe-chinfo)]
                               [partner (#%channel-partner maybe-chinfo)])
                           (hash-remove! (ssh-connection-service-channels self) id)
                           (ssh-channel.destruct channel)
                           (values self (make-ssh:msg:channel:close #:recipient partner)))])]
            
            [else (values self #false)]))))

(define ssh-connection-datum-evt : SSH-Service-Datum-Evt
  (lambda [self]
    (with-asserts ([self ssh-connection-service?])
      (let filter-map ([chinfos : (Listof #%Channel) (hash-values (ssh-connection-service-channels self))]
                       [evts : (Listof (Evtof (Pairof SSH-Service SSH-Service-Reply))) null])
        (cond [(null? chinfos) (and (pair? evts) (apply choice-evt evts))]
              [else (let* ([chinfo (car chinfos)]
                           [e (ssh-channel.datum-evt (#%channel-entity chinfo) (#%channel-partner chinfo))])
                      (cond [(and e) (filter-map (cdr chinfos) (cons (ssh-connection-wrap-evt self e chinfo) evts))]
                            [else (filter-map (cdr chinfos) evts)]))])))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-wrap-evt : (-> SSH-Connection-Service (Evtof (Pairof SSH-Channel SSH-Channel-Reply)) #%Channel (Evtof (Pairof SSH-Service SSH-Service-Reply)))
  (lambda [self evt chinfo]
    (define (wrap [chply : (Pairof SSH-Channel SSH-Channel-Reply)]) : (Pairof SSH-Service SSH-Service-Reply)
      (define channel : SSH-Channel (car chply))
      (define replies : SSH-Channel-Reply (cdr chply))

      (cond [(or (ssh:msg:channel:close? replies) (and (pair? replies) (ormap ssh:msg:channel:close? replies)))
             (hash-remove! (ssh-connection-service-channels self) (#%channel-self chinfo))
             (ssh-channel.destruct channel)]
            [(not (eq? (#%channel-entity chinfo) channel))
             (set-#%channel-entity! chinfo channel)])
      
      (cons self replies))
    
    (wrap-evt evt wrap)))
