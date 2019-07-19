#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4254

(provide (all-defined-out))

(require digimon/format)

(require "channel.rkt")
(require "message.rkt")

(require "../message.rkt")
(require "../message/channel.rkt")
(require "../message/connection.rkt")

(require "../assignment.rkt")
(require "../diagnostics.rkt")

(require "../../datatype.rkt")
(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Port (Mutable-HashTable Index SSH-Spot))
(define-type SSH-Channel-Port-Reply (U SSH-Message (Listof SSH-Message) False))

(define ssh-window-upsize : Index (assert (- (expt 2 32) 1) index?))

(struct ssh-spot
  ([channel : SSH-Channel]
   [partner : (Option Index)] ; #false => waiting for the confirmation 
   [incoming-window : Index]
   [outgoing-window : Index]
   [parcel : Bytes]
   [incoming-upwindow : Index]
   [outgoing-upwindow : Index]
   [pending-data : (Listof SSH-Message)]
   [incoming-eof? : Boolean]
   [outgoing-eof? : Boolean]
   [incoming-traffic : Natural]
   [outgoing-traffic : Natural])
  #:type-name SSH-Spot
  #:mutable)

(define ssh-chport-destruct : (-> SSH-Channel-Port Void)
  (lambda [self]
    (for ([chport (in-hash-values self)])
      (ssh-channel.destruct (ssh-spot-channel chport)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-chport-filter : (-> SSH-Channel-Port SSH-Message SSH-Configuration (U SSH-Message (Listof SSH-Message) False))
  (lambda [self msg rfc]
    (cond [(ssh:msg:channel:data? msg)
           (define chid : Index (ssh:msg:channel:data-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))

           (and maybe-chport
                (let*-values ([(octets) (ssh:msg:channel:data-octets msg)]
                              [(maybe-partner maybe-adjust) (ssh-chport-check-incoming-parcel! maybe-chport octets)])
                  (and maybe-partner
                       (let*-values ([(channel) (ssh-spot-channel maybe-chport)]
                                     [(channel++ feedback) (ssh-channel.consume channel octets maybe-partner)])
                         (ssh-chport-update-channel-port! self
                                                          maybe-chport channel++ feedback maybe-adjust)))))]
          
          [(ssh:msg:channel:extended:data? msg)
           (define chid : Index (ssh:msg:channel:extended:data-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))
           
           (and maybe-chport
                (let*-values ([(octets) (ssh:msg:channel:extended:data-octets msg)]
                              [(maybe-partner maybe-adjust) (ssh-chport-check-incoming-parcel! maybe-chport octets)])
                  (and maybe-partner
                       (let*-values ([(channel) (ssh-spot-channel maybe-chport)]
                                     [(channel++ feedback) (ssh-channel.consume channel octets (ssh:msg:channel:extended:data-type msg) maybe-partner)])
                         (ssh-chport-update-channel-port! self maybe-chport channel++ feedback maybe-adjust)))))]
          
          [(ssh:msg:channel:eof? msg)
           (define chid : Index (ssh:msg:channel:eof-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))

           (and maybe-chport
                (let ([channel (ssh-spot-channel maybe-chport)]
                      [partner (ssh-channel-incoming-partner maybe-chport)])
                  (and partner
                       (let-values ([(channel++ feedback) (ssh-channel.consume channel eof partner)])
                         (set-ssh-spot-incoming-eof?! maybe-chport #true)
                         (ssh-chport-update-channel-port! self maybe-chport channel++ feedback)))))]
          
          [(ssh:msg:channel:open? msg)
           (define type : Symbol (ssh:msg:channel:open-type msg))
           (define partner : Index (ssh:msg:channel:open-sender msg))
           (define outgoing-window : Index (ssh:msg:channel:open-window-size msg)) ; uint32 field, never larger than 2^32 - 1;
           (define outgoing-capacity : Index (ssh:msg:channel:open-packet-capacity msg))
           (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))
           
           (cond [(not λchannel) (make-ssh:open:unknown:channel:type partner)]
                 [(memq (car λchannel) ($ssh-disabled-channel-types rfc)) (make-ssh:open:administratively:prohibited partner)]
                 [else (with-handlers ([exn:fail:out-of-memory? (λ [[e : exn]] (make-ssh:open:resource:shortage #:source (cdr λchannel) partner (exn-message e)))])
                         (define self-id : Index (ssh-channel-eq-uuid msg self))
                         (define maybe-channel : (U SSH-Channel SSH-Message) ((cdr λchannel) type self-id msg rfc))
                         (cond [(ssh-message? maybe-channel) maybe-channel]
                               [else (let* ([incoming-capacity (min ($ssh-payload-capacity rfc) ($ssh-channel-packet-capacity rfc) outgoing-capacity)]
                                            [incoming-window (min ($ssh-channel-initial-window-size rfc) ssh-window-upsize)])
                                       (hash-set! self self-id
                                                  (ssh-spot maybe-channel partner incoming-window outgoing-window
                                                                    (make-bytes (- incoming-capacity (ssh-bstring-length #"")))
                                                                    incoming-window outgoing-window null #false #false 0 0))
                                       (make-ssh:msg:channel:open:confirmation #:recipient partner #:sender self-id
                                                                               #:window-size incoming-window #:packet-capacity incoming-capacity))]))])]
          
          [(ssh:msg:channel:request? msg)
           (define reply? : Boolean (ssh:msg:channel:request-reply? msg))
           (define chid : Index (ssh:msg:channel:request-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))
           
           (and maybe-chport
                (let ([channel (ssh-spot-channel maybe-chport)]
                      [partner (ssh-spot-partner maybe-chport)])
                  (and partner
                       (let-values ([(channel++ okay?) (ssh-channel.response channel msg rfc)])
                         (unless (eq? channel channel++)
                           (set-ssh-spot-channel! maybe-chport channel++))
                         
                         (and reply?
                              (if (not okay?)
                                  (make-ssh:msg:channel:failure #:recipient partner)
                                  (make-ssh:msg:channel:success #:recipient partner)))))))]
          
          [(ssh:msg:channel:window:adjust? msg)
           (define chid : Index (ssh:msg:channel:window:adjust-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))

           (and maybe-chport
                (ssh-spot-partner maybe-chport)
                (let* ([increment (ssh:msg:channel:window:adjust-increment msg)]
                       [outgoing-window++ (+ (ssh-spot-outgoing-window maybe-chport) increment)]
                       [outgoing-window++ (if (> outgoing-window++ ssh-window-upsize) ssh-window-upsize outgoing-window++)]
                       [pending-data (ssh-spot-pending-data maybe-chport)])
                  (set-ssh-spot-pending-data! maybe-chport null)
                  (set-ssh-spot-outgoing-window! maybe-chport outgoing-window++)
                  (set-ssh-spot-outgoing-upwindow! maybe-chport outgoing-window++)
                  (ssh-log-message 'debug "Channel[0x~a]: the outgoing window is incremented to ~a after ~a consumed"
                                   (number->string chid 16) (~size outgoing-window++)
                                   (~size (ssh-spot-outgoing-traffic maybe-chport)))
                  (ssh-chport-check-outgoing-parcels! self maybe-chport pending-data chid)))]
          
          [(ssh:msg:channel:close? msg)
           (define chid : Index (ssh:msg:channel:close-recipient msg))
           (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self chid (λ [] #false))))
           
           (and maybe-chport
                (let ([channel (ssh-spot-channel maybe-chport)]
                      [partner (ssh-spot-partner maybe-chport)])
                  (hash-remove! self chid)
                  (ssh-channel.destruct channel)
                  (and partner #| should not be #false |#
                       (make-ssh:msg:channel:close #:recipient partner))))]
          
          [else #false])))

(define ssh-chport-datum-evt : (-> SSH-Channel-Port (Option (Evtof SSH-Channel-Port-Reply)))
  (lambda [self]
    (let filter-map ([chports : (Listof SSH-Spot) (hash-values self)]
                     [evts : (Listof (Evtof SSH-Channel-Port-Reply)) null])
      (cond [(null? chports) (and (pair? evts) (apply choice-evt evts))]
            [else (let* ([chport (car chports)]
                         [partner (ssh-spot-partner chport)])
                    (define e : (Option (Evtof (Pairof SSH-Channel SSH-Channel-Reply)))
                      (and partner (ssh-channel.datum-evt (ssh-spot-channel chport) (ssh-spot-parcel chport) partner)))
                    (cond [(and e) (filter-map (cdr chports) (cons (ssh-chport-wrap-evt self e chport) evts))]
                          [else (filter-map (cdr chports) evts)]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-chport-wrap-evt : (-> SSH-Channel-Port (Evtof (Pairof SSH-Channel SSH-Channel-Reply)) SSH-Spot (Evtof SSH-Channel-Port-Reply))
  (lambda [self evt chport]
    (wrap-evt evt
              (λ [[chply : (Pairof SSH-Channel SSH-Channel-Reply)]] : SSH-Channel-Port-Reply
                (ssh-chport-update-channel-port! self chport (car chply) (cdr chply))))))

(define ssh-chport-update-channel-port! : (->* (SSH-Channel-Port SSH-Spot SSH-Channel SSH-Channel-Reply) ((Option SSH-Message)) SSH-Channel-Reply)
  (lambda [self chport channel reply [maybe-adjust #false]]
    (unless (eq? (ssh-spot-channel chport) channel)
      (set-ssh-spot-channel! chport channel))

    (let ([replies (ssh-chport-check-outgoing-parcels! self chport reply (ssh-channel-id channel))])
      (cond [(not maybe-adjust) replies]
            [(ssh-message? replies) (list maybe-adjust replies)]
            [(list? replies) (cons maybe-adjust replies)]
            [else maybe-adjust]))))

(define ssh-chport-check-outgoing-parcels! : (-> SSH-Channel-Port SSH-Spot SSH-Channel-Reply Index SSH-Channel-Reply)
  (lambda [self chport replies channel-id]
    (define-values (outgoing-replies pending-data close?)
      (cond [(not replies) (values #false null #false)]
            [(ssh-message? replies) (ssh-chport-check-outgoing-parcel! chport replies)]
            [else (let partition : (Values (Listof SSH-Message) (Listof SSH-Message) Boolean)
                    ([outgoings : (Listof SSH-Message) null]
                     [pendings : (Listof SSH-Message) null]
                     [replies : (Listof SSH-Message) replies]
                     [has-close? : Boolean #false])
                    (cond [(null? replies) (values (reverse outgoings) pendings has-close?)]
                          [else (let-values ([(reply pending close?) (ssh-chport-check-outgoing-parcel! chport (car replies))])
                                  (partition (if (not reply) outgoings (cons reply outgoings))
                                             (append pendings pending)
                                             (if (not close?) (cdr replies) null)
                                             close?))]))]))
    
    (cond [(and close?)
           (hash-remove! self channel-id)
           (ssh-channel.destruct (ssh-spot-channel chport))]
          [(pair? pending-data)
           (set-ssh-spot-pending-data! chport (append (ssh-spot-pending-data chport) pending-data))])

    (cond [(ssh-message? outgoing-replies) (ssh-log-outgoing-message outgoing-replies)]
          [(list? outgoing-replies) (for-each ssh-log-outgoing-message outgoing-replies)])
    
    outgoing-replies))

(define ssh-chport-check-outgoing-parcel! : (-> SSH-Spot SSH-Message (Values (Option SSH-Message) (Listof SSH-Message) Boolean))
  (lambda [chport reply]
    (define octets : (U Bytes Void)
      (cond [(ssh:msg:channel:data? reply) (ssh:msg:channel:data-octets reply)]
            [(ssh:msg:channel:extended:data? reply) (ssh:msg:channel:extended:data-octets reply)]))

    (cond [(void? octets) (values reply null (ssh:msg:channel:close? reply))]
          [(ssh-spot-outgoing-eof? chport) (values #false null #false)]
          [else (let* ([traffic (ssh-bstring-length octets)]
                       [outgoing-window-- (- (ssh-spot-outgoing-window chport) traffic)])
                  ; the traffic always less than the channel capacity by implementation
                  (cond [(not (index? outgoing-window--)) (values #false (list reply) #false)]
                        [else (let ([outgoing-traffic++ (+ (ssh-spot-outgoing-traffic chport) traffic)]
                                    [consumption (- (ssh-spot-outgoing-upwindow chport) outgoing-window--)])
                                (set-ssh-spot-outgoing-window! chport outgoing-window--)
                                (set-ssh-spot-outgoing-traffic! chport outgoing-traffic++)
                                (ssh-log-message 'debug "Channel[0x~a]: the outgoing window will be decremented to ~a by ~a"
                                                 (number->string (ssh-channel-id (ssh-spot-channel chport)) 16)
                                                 (~size outgoing-window-- #:precision '(= 6)) (~size consumption))
                                (values reply null #false))]))])))

(define ssh-chport-check-incoming-parcel! : (-> SSH-Spot Bytes (Values (Option Index) (Option SSH-MSG-CHANNEL-WINDOW-ADJUST)))
  (lambda [chport octets]
    (define partner : (Option Index) (ssh-channel-incoming-partner chport))
    (define traffic : Natural (ssh-bstring-length octets))
    (define incoming-upwindow : Index (ssh-spot-incoming-upwindow chport))
    (define incoming-window : Index (ssh-spot-incoming-window chport))
    (define incoming-window-- : Integer (- incoming-window traffic))
    (define channel-capacity : Natural (ssh-bstring-length (ssh-spot-parcel chport)))
    (define self-str : String (number->string (ssh-channel-id (ssh-spot-channel chport)) 16))
    
    (cond [(not partner)
           (ssh-log-message 'warning "Channel[0x~a]: waiting for the confirmation" self-str)
           (values #false #false)]
          [(> traffic (+ channel-capacity (ssh-bstring-length #""))) ; stupid OpenSSH
           (ssh-log-message 'warning "Channel[0x~a]: packet is too big: ~a > ~a" self-str (~size traffic) (~size channel-capacity))
           (values #false #false)]
          [(not (index? incoming-window--))
           (ssh-log-message 'warning "Channel[0x~a]: the incoming window is too small: ~a < ~a" self-str (~size incoming-window #:precision '(= 6)) (~size traffic))
           (values #false #false)]
          [else (let ([consumption (- incoming-upwindow incoming-window--)])
                  ; see `channel-check-window` in channels.c of OpenSSH
                  (set-ssh-spot-incoming-traffic! chport (+ (ssh-spot-incoming-traffic chport) traffic))
                  (if (and (< incoming-window-- (* channel-capacity 2)) (index? consumption))
                      (let ([incoming-str (~size incoming-upwindow)])
                        (set-ssh-spot-incoming-window! chport incoming-upwindow)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is incremented to ~a after ~a consumed"
                                         self-str incoming-str (~size (ssh-spot-incoming-traffic chport)))
                        (values partner (make-ssh:msg:channel:window:adjust #:recipient partner #:increment consumption)))
                      (let ([incoming-str (~size incoming-window-- #:precision '(= 6))])
                        (set-ssh-spot-incoming-window! chport incoming-window--)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is decremented to ~a by ~a"
                                         self-str incoming-str (~size consumption))
                        (values partner #false))))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-incoming-partner : (-> SSH-Spot (Option Index))
  (lambda [self]
    (and (not (ssh-spot-incoming-eof? self))
         (ssh-spot-partner self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-eq-uuid : (case-> [Any -> Index]
                                      [Any HashTableTop -> Index])
  (case-lambda
    [(object)
     (let-values ([(bodybits randbits) (values 28 4)])
       (assert (let ([body (bitwise-bit-field (eq-hash-code object) 0 bodybits)]
                     [rand (random (arithmetic-shift 1 randbits))])
                 (bitwise-ior (arithmetic-shift rand bodybits) body))
               index?))]
    [(object uuidbase)
     (let uuid ([composed-object : Any object])
       (let ([id (ssh-channel-eq-uuid composed-object)])
         (cond [(not (hash-has-key? uuidbase id)) id]
               [else (uuid (cons composed-object id))])))]))

