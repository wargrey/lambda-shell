#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4254

(provide (all-defined-out))

(require digimon/format)

(require "message.rkt")
(require "channel.rkt")
(require "chport.rkt")

(require "../message.rkt")
(require "../service.rkt")
(require "../assignment.rkt")
(require "../diagnostics.rkt")

(require "../message/channel.rkt")
(require "../message/connection.rkt")
(require "../assignment/message.rkt")

(require "../../datatype.rkt")
(require "../../configuration.rkt")

(struct ssh-connection-service ssh-service
  ([ports : (Mutable-HashTable Index SSH-Channel-Port)])
  #:type-name SSH-Connection-Service)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [name user session rfc]
    (ssh-connection-service (super-ssh-service #:name name #:user user #:session session #:preference rfc
                                               #:range ssh-connection-range #:log-outgoing ssh-log-outgoing-message
                                               #:response ssh-connection-response #:datum-evt ssh-connection-datum-evt
                                               #:destruct ssh-connection-destruct)
                            (make-hasheq))))

(define ssh-connection-destruct : SSH-Service-Destructor
  (lambda [self]
    (with-asserts ([self ssh-connection-service?])
      (for ([chport (in-hash-values (ssh-connection-service-ports self))])
        (ssh-channel.destruct (ssh-channel-port-entity chport))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest]
    (with-asserts ([self ssh-connection-service?])
      (define request : (Option SSH-Message) (ssh-filter-connection-message brequest))
      (define unsafe-id : Index (ssh-bytes-uint32-car brequest))
      (define maybe-chport : (Option SSH-Channel-Port) (and request (hash-ref (ssh-connection-service-ports self) unsafe-id (λ [] #false))))

      (define response : SSH-Service-Reply
        (cond [(ssh:msg:channel:data? request)
               (and maybe-chport
                    (let*-values ([(octets) (ssh:msg:channel:data-octets request)]
                                  [(maybe-partner maybe-adjust) (ssh-connection-check-incoming-parcel! maybe-chport octets)])
                      (and maybe-partner
                           (let*-values ([(channel) (ssh-channel-port-entity maybe-chport)]
                                         [(channel++ feedback) (ssh-channel.consume channel octets maybe-partner)])
                             (ssh-connection-update-channel-port! self maybe-chport channel++ feedback maybe-adjust)))))]
              
              [(ssh:msg:channel:extended:data? request)
               (and maybe-chport
                    (let*-values ([(octets) (ssh:msg:channel:extended:data-octets request)]
                                  [(maybe-partner maybe-adjust) (ssh-connection-check-incoming-parcel! maybe-chport octets)])
                      (and maybe-partner
                           (let*-values ([(channel) (ssh-channel-port-entity maybe-chport)]
                                         [(channel++ feedback) (ssh-channel.consume channel octets (ssh:msg:channel:extended:data-type request) maybe-partner)])
                             (ssh-connection-update-channel-port! self maybe-chport channel++ feedback maybe-adjust)))))]
              
              [(ssh:msg:channel:eof? request)
               (and maybe-chport
                    (let ([channel (ssh-channel-port-entity maybe-chport)]
                          [partner (ssh-channel-incoming-partner maybe-chport)])
                      (and partner
                           (let-values ([(channel++ feedback) (ssh-channel.consume channel eof partner)])
                             (set-ssh-channel-port-incoming-eof?! maybe-chport #true)
                             (ssh-connection-update-channel-port! self maybe-chport channel++ feedback)))))]
              
              [(ssh:msg:channel:open? request)
               (define rfc : SSH-Configuration (ssh-service-preference self))
               (define type : Symbol (ssh:msg:channel:open-type request))
               (define partner : Index (ssh:msg:channel:open-sender request))
               (define outgoing-window : Index (ssh:msg:channel:open-window-size request)) ; uint32 field, never larger than 2^32 - 1;
               (define outgoing-capacity : Index (ssh:msg:channel:open-packet-capacity request))
               (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))
               
               (cond [(not λchannel) (make-ssh:open:unknown:channel:type partner)]
                     [(memq (car λchannel) ($ssh-disabled-channel-types rfc)) (make-ssh:open:administratively:prohibited partner)]
                     [else (with-handlers ([exn:fail:out-of-memory? (λ [[e : exn]] (make-ssh:open:resource:shortage #:source (cdr λchannel) partner (exn-message e)))])
                             (define self-id : Index (ssh-channel-eq-uuid request (ssh-connection-service-ports self)))
                             (define maybe-channel : (U SSH-Channel SSH-Message) ((cdr λchannel) type self-id request rfc))
                             (cond [(ssh-message? maybe-channel) maybe-channel]
                                   [else (let* ([incoming-capacity (min ($ssh-payload-capacity rfc) ($ssh-channel-packet-capacity rfc) outgoing-capacity)]
                                                [incoming-window (min ($ssh-channel-initial-window-size rfc) ssh-window-upsize)])
                                           (hash-set! (ssh-connection-service-ports self) self-id
                                                      (ssh-channel-port maybe-channel partner incoming-window outgoing-window
                                                                        (make-bytes (- incoming-capacity (ssh-bstring-length #"")))
                                                                        incoming-window outgoing-window null #false #false 0 0))
                                           (make-ssh:msg:channel:open:confirmation #:recipient partner #:sender self-id
                                                                                   #:window-size incoming-window #:packet-capacity incoming-capacity))]))])]
              
              [(ssh:msg:channel:request? request)
               (define rfc : SSH-Configuration (ssh-service-preference self))
               (define reply? : Boolean (ssh:msg:channel:request-reply? request))
               
               (and maybe-chport
                    (let ([channel (ssh-channel-port-entity maybe-chport)]
                          [partner (ssh-channel-port-partner maybe-chport)])
                      (and partner
                           (let-values ([(channel++ okay?) (ssh-channel.response channel request rfc)])
                             (unless (eq? channel channel++)
                               (set-ssh-channel-port-entity! maybe-chport channel++))
                             
                             (and reply?
                                  (if (not okay?)
                                      (make-ssh:msg:channel:failure #:recipient partner)
                                      (make-ssh:msg:channel:success #:recipient partner)))))))]

              [(ssh:msg:channel:window:adjust? request)
               (and maybe-chport
                    (ssh-channel-port-partner maybe-chport)
                    (let* ([increment (ssh:msg:channel:window:adjust-increment request)]
                           [outgoing-window++ (+ (ssh-channel-port-outgoing-window maybe-chport) increment)]
                           [outgoing-window++ (if (> outgoing-window++ ssh-window-upsize) ssh-window-upsize outgoing-window++)]
                           [pending-data (ssh-channel-port-pending-data maybe-chport)])
                      (set-ssh-channel-port-pending-data! maybe-chport null)
                      (set-ssh-channel-port-outgoing-window! maybe-chport outgoing-window++)
                      (set-ssh-channel-port-outgoing-upwindow! maybe-chport outgoing-window++)
                      (ssh-log-message 'debug "Channel[0x~a]: the outgoing window is incremented to ~a after ~a consumed"
                                       (number->string unsafe-id 16) (~size outgoing-window++)
                                       (~size (ssh-channel-port-outgoing-traffic maybe-chport)))
                      (ssh-connection-check-outgoing-parcels! self maybe-chport pending-data unsafe-id)))]
              
              [(ssh:msg:channel:close? request)
               (and maybe-chport
                    (let ([channel (ssh-channel-port-entity maybe-chport)]
                          [partner (ssh-channel-port-partner maybe-chport)])
                      (hash-remove! (ssh-connection-service-ports self) unsafe-id)
                      (ssh-channel.destruct channel)
                      (and partner #| should not be #false |#
                           (make-ssh:msg:channel:close #:recipient partner))))]
              
              [else #false]))

      (values self response))))

(define ssh-connection-datum-evt : SSH-Service-Datum-Evt
  (lambda [self]
    (with-asserts ([self ssh-connection-service?])
      (let filter-map ([chports : (Listof SSH-Channel-Port) (hash-values (ssh-connection-service-ports self))]
                       [evts : (Listof (Evtof (Pairof SSH-Service SSH-Service-Reply))) null])
        (cond [(null? chports) (and (pair? evts) (apply choice-evt evts))]
              [else (let* ([chport (car chports)]
                           [partner (ssh-channel-port-partner chport)])
                      (define e : (Option (Evtof (Pairof SSH-Channel SSH-Channel-Reply)))
                        (and partner (ssh-channel.datum-evt (ssh-channel-port-entity chport) (ssh-channel-port-parcel chport) partner)))
                      (cond [(and e) (filter-map (cdr chports) (cons (ssh-connection-wrap-evt self e chport) evts))]
                            [else (filter-map (cdr chports) evts)]))])))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-wrap-evt : (-> SSH-Connection-Service (Evtof (Pairof SSH-Channel SSH-Channel-Reply)) SSH-Channel-Port
                                      (Evtof (Pairof SSH-Service SSH-Service-Reply)))
  (lambda [self evt chport]
    (wrap-evt evt
              (λ [[chply : (Pairof SSH-Channel SSH-Channel-Reply)]] : (Pairof SSH-Service SSH-Service-Reply)
                (cons self (ssh-connection-update-channel-port! self chport (car chply) (cdr chply)))))))

(define ssh-connection-update-channel-port! : (->* (SSH-Connection-Service SSH-Channel-Port SSH-Channel SSH-Channel-Reply) ((Option SSH-Message)) SSH-Channel-Reply)
  (lambda [self chport channel reply [maybe-adjust #false]]
    (unless (eq? (ssh-channel-port-entity chport) channel)
      (set-ssh-channel-port-entity! chport channel))

    (let ([replies (ssh-connection-check-outgoing-parcels! self chport reply (ssh-channel-id channel))])
      (cond [(not maybe-adjust) replies]
            [(ssh-message? replies) (list maybe-adjust replies)]
            [(list? replies) (cons maybe-adjust replies)]
            [else maybe-adjust]))))

(define ssh-connection-check-outgoing-parcels! : (-> SSH-Connection-Service SSH-Channel-Port SSH-Channel-Reply Index SSH-Channel-Reply)
  (lambda [self chport replies channel-id]
    (define-values (outgoing-replies pending-data close?)
      (cond [(not replies) (values #false null #false)]
            [(ssh-message? replies) (ssh-connection-check-outgoing-parcel! self chport replies)]
            [else (let partition : (Values (Listof SSH-Message) (Listof SSH-Message) Boolean)
                    ([outgoings : (Listof SSH-Message) null]
                     [pendings : (Listof SSH-Message) null]
                     [replies : (Listof SSH-Message) replies])
                    (cond [(null? replies) (values (reverse outgoings) pendings #false)]
                          [else (let-values ([(reply pending close?) (ssh-connection-check-outgoing-parcel! self chport (car replies))])
                                  (partition (if (not reply) outgoings (cons reply outgoings))
                                             (append pendings pending)
                                             (if (not close?) (cdr replies) null)))]))]))
    
    (cond [(and close?)
           (hash-remove! (ssh-connection-service-ports self) channel-id)
           (ssh-channel.destruct (ssh-channel-port-entity chport))]
          [(pair? pending-data)
           (set-ssh-channel-port-pending-data! chport (append (ssh-channel-port-pending-data chport) pending-data))])

    outgoing-replies))

(define ssh-connection-check-outgoing-parcel! : (-> SSH-Connection-Service SSH-Channel-Port SSH-Message (Values (Option SSH-Message) (Listof SSH-Message) Boolean))
  (lambda [self chport reply]
    (define octets : (U Bytes Void)
      (cond [(ssh:msg:channel:data? reply) (ssh:msg:channel:data-octets reply)]
            [(ssh:msg:channel:extended:data? reply) (ssh:msg:channel:extended:data-octets reply)]))

    (cond [(void? octets) (values reply null (ssh:msg:channel:close? reply))]
          [(ssh-channel-port-outgoing-eof? chport) (values #false null #false)]
          [else (let* ([traffic (ssh-bstring-length octets)]
                       [outgoing-window-- (- (ssh-channel-port-outgoing-window chport) traffic)])
                  ; the traffic always less than the channel capacity by implementation
                  (cond [(not (index? outgoing-window--)) (values #false (list reply) #false)]
                        [else (let ([outgoing-traffic++ (+ (ssh-channel-port-outgoing-traffic chport) traffic)]
                                    [consumption (- (ssh-channel-port-outgoing-upwindow chport) outgoing-window--)])
                                (set-ssh-channel-port-outgoing-window! chport outgoing-window--)
                                (set-ssh-channel-port-outgoing-traffic! chport outgoing-traffic++)
                                (ssh-log-message 'debug "Channel[0x~a]: the outgoing window will be decremented to ~a by ~a"
                                                 (number->string (ssh-channel-id (ssh-channel-port-entity chport)) 16)
                                                 (~size outgoing-window-- #:precision '(= 6)) (~size consumption))
                                (values reply null #false))]))])))

(define ssh-connection-check-incoming-parcel! : (-> SSH-Channel-Port Bytes (Values (Option Index) (Option SSH-MSG-CHANNEL-WINDOW-ADJUST)))
  (lambda [chport octets]
    (define partner : (Option Index) (ssh-channel-incoming-partner chport))
    (define traffic : Natural (ssh-bstring-length octets))
    (define incoming-upwindow : Index (ssh-channel-port-incoming-upwindow chport))
    (define incoming-window : Integer (- (ssh-channel-port-incoming-window chport) traffic))
    (define channel-capacity : Natural (ssh-bstring-length (ssh-channel-port-parcel chport)))
    
    (cond [(not (and partner (< traffic channel-capacity) (index? incoming-window))) (values #false #false)]
          [else (let* ([consumption (- incoming-upwindow incoming-window)]
                       [self-str (number->string (ssh-channel-id (ssh-channel-port-entity chport)) 16)])
                  ; see `channel-check-window` in channels.c of OpenSSH
                  (set-ssh-channel-port-incoming-traffic! chport (+ (ssh-channel-port-incoming-traffic chport) traffic))
                  (if (and (index? consumption)
                           (or (> consumption (* channel-capacity 4))
                               (< incoming-window (/ incoming-upwindow 4))))
                      (let ([incoming-str (~size incoming-upwindow)])
                        (set-ssh-channel-port-incoming-window! chport incoming-upwindow)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is incremented to ~a after ~a consumed"
                                         self-str incoming-str (~size (ssh-channel-port-incoming-traffic chport)))
                        (values partner (make-ssh:msg:channel:window:adjust #:recipient partner #:increment consumption)))
                      (let ([incoming-str (~size incoming-window #:precision '(= 6))])
                        (set-ssh-channel-port-incoming-window! chport incoming-window)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is decremented to ~a by ~a"
                                         self-str incoming-str (~size consumption))
                        (values partner #false))))])))
