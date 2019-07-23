#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4254

(provide (all-defined-out))

(require digimon/format)

(require "chid.rkt")
(require "channel.rkt")
(require "message.rkt")
(require "channel/application.rkt")

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

;; NOTE
; Peers may not count on the size of channel data when computing the amount of data.
; We count on it, and are tolerant of those do not.
(define ssh-channel-data-fault-tolerance : Positive-Fixnum (ssh-bstring-length #""))
(define ssh-window-upsize : Index (assert (- (expt 2 32) 1) index?))

(struct ssh-spot
  ([channel : SSH-Channel]
   [self-id : Index]
   [peer-id : (Option Index)]
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
(define ssh-chport-transmit : (-> SSH-Channel-Port SSH-Message SSH-Configuration Boolean (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc server?]
    (cond [(ssh:msg:channel:open? msg) (ssh-chport-filter:opening self msg rfc server?)]
          [else #| other channel-related messages should be transmitted via channel's API |# msg])))

;; TODO
; RFC4254 says, if the SSH-MSG-CHANNEL-REQUEST wants reply, the recipient may response with
; either SSH-MSG-CHANNEL-SUCCESS, SSH-MSG-CHANNEL-FAILURE or some message specific.
(define ssh-chport-filter : (-> SSH-Channel-Port SSH-Message SSH-Configuration Boolean SSH-Channel-Port-Reply)
  (lambda [self msg rfc server?]
    (cond [(ssh:msg:channel:data? msg) (ssh-chport-filter:data self msg rfc)]
          [(ssh:msg:channel:extended:data? msg) (ssh-chport-filter:extended:data self msg rfc)]
          [(ssh:msg:channel:window:adjust? msg) (ssh-chport-filter:window:adjust self msg rfc)]
          [(ssh:msg:channel:request? msg) (ssh-chport-filter:request self msg rfc)]
          [(ssh:msg:channel:open? msg) (ssh-chport-filter:open self msg rfc server?)]
          [(ssh:msg:channel:close? msg) (ssh-chport-filter:close self msg rfc)]
          [(ssh:msg:channel:eof? msg) (ssh-chport-filter:eof self msg rfc)]
          [else #false])))

(define ssh-chport-filter* : (-> SSH-Channel-Port SSH-Message SSH-Configuration Boolean (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc server?]
    (cond [(ssh:msg:channel:data? msg) (ssh-chport-filter:data self msg rfc)]
          [(ssh:msg:channel:extended:data? msg) (ssh-chport-filter:extended:data self msg rfc)]
          [(ssh:msg:channel:window:adjust? msg) (ssh-chport-filter:window:adjust self msg rfc)]
          [(ssh:msg:channel:request? msg) (ssh-chport-filter:request self msg rfc)]
          [(ssh:msg:channel:success? msg) (ssh-chport-filter:success self msg rfc)]
          [(ssh:msg:channel:open:confirmation? msg) (ssh-chport-filter:confirmation self msg rfc server?)]
          [(ssh:msg:channel:close? msg) (ssh-chport-filter:close self msg rfc)]
          [(ssh:msg:channel:eof? msg) (ssh-chport-filter:eof self msg rfc)]
          [(ssh:msg:channel:failure? msg) (ssh-chport-filter:failure self msg rfc)]
          [else #false])))

(define ssh-chport-datum-evt : (-> SSH-Channel-Port (Option (Evtof SSH-Channel-Port-Reply)))
  (lambda [self]
    (let filter-map ([chports : (Listof SSH-Spot) (hash-values self)]
                     [evts : (Listof (Evtof SSH-Channel-Port-Reply)) null])
      (cond [(null? chports) (and (pair? evts) (apply choice-evt evts))]
            [else (let* ([chport (car chports)]
                         [partner (ssh-spot-peer-id chport)])
                    (define e : (Option (Evtof SSH-Channel-Reply))
                      (and partner (ssh-channel.datum-evt (ssh-spot-channel chport) (ssh-spot-parcel chport) partner)))
                    (cond [(and e) (filter-map (cdr chports) (cons (ssh-chport-wrap-evt self e chport) evts))]
                          [else (filter-map (cdr chports) evts)]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-chport-filter:opening : (-> SSH-Channel-Port SSH-MSG-CHANNEL-OPEN SSH-Configuration Boolean (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc server?]
    (define type : Symbol (ssh:msg:channel:open-type msg))
    (define self-id : Index (ssh:msg:channel:open-sender msg))
    (define incoming-window : Index (ssh:msg:channel:open-window-size msg)) ; uint32 field, never larger than 2^32 - 1;
    (define incoming-capacity : Index (ssh:msg:channel:open-packet-capacity msg))
    (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))

    (cond [(not λchannel) (box (make-ssh:open:unknown:channel:type self-id))]
          [(memq (car λchannel) ($ssh-disabled-channel-types rfc)) (box (make-ssh:open:administratively:prohibited self-id))]
          [else (let ([app-channel (make-ssh-application-channel type self-id msg rfc)])
                  (cond [(ssh-message? app-channel) (box app-channel)]
                        [else (let ([outgoing-capacity (min ($ssh-payload-capacity rfc) ($ssh-channel-packet-capacity rfc) incoming-capacity)])
                                (hash-set! self self-id
                                           (ssh-spot app-channel self-id self-id incoming-window incoming-window
                                                     (make-bytes (max (- outgoing-capacity ssh-channel-data-fault-tolerance) 0))
                                                     incoming-window incoming-window null #false #false 0 0))
                                msg)]))])))

(define ssh-chport-filter:open : (-> SSH-Channel-Port SSH-MSG-CHANNEL-OPEN SSH-Configuration Boolean SSH-Channel-Port-Reply)
  (lambda [self msg rfc server?]
    (define type : Symbol (ssh:msg:channel:open-type msg))
    (define partner : Index (ssh:msg:channel:open-sender msg))
    (define outgoing-window : Index (ssh:msg:channel:open-window-size msg)) ; uint32 field, never larger than 2^32 - 1;
    (define outgoing-capacity : Index (ssh:msg:channel:open-packet-capacity msg))
    (define λchannel : (Option (SSH-Nameof SSH-Channel#)) (assq type (ssh-registered-channels)))
    
    (cond [(not λchannel) (make-ssh:open:unknown:channel:type partner)]
          [(memq (car λchannel) ($ssh-disabled-channel-types rfc)) (make-ssh:open:administratively:prohibited partner)]
          [(and (not server?) (eq? (car λchannel) 'session)) (make-ssh:open:administratively:prohibited partner)]
          [else (with-handlers ([exn:fail:out-of-memory? (λ [[e : exn]] (make-ssh:open:resource:shortage #:source (cdr λchannel) partner (exn-message e)))])
                  (define self-id : Index (make-ssh-channel-uuid make-ssh-channel-id self))
                  (define maybe-channel : (U SSH-Channel SSH-Message) ((cdr λchannel) type self-id msg rfc))
                  (cond [(ssh-message? maybe-channel) maybe-channel]
                        [else (let* ([incoming-capacity (min ($ssh-payload-capacity rfc) ($ssh-channel-packet-capacity rfc) outgoing-capacity)]
                                     [incoming-window (min ($ssh-channel-initial-window-size rfc) ssh-window-upsize)])
                                (hash-set! self self-id
                                           (ssh-spot maybe-channel self-id partner incoming-window outgoing-window
                                                     (make-bytes (max (- incoming-capacity ssh-channel-data-fault-tolerance) 0))
                                                     incoming-window outgoing-window null #false #false 0 0))
                                (make-ssh:msg:channel:open:confirmation #:recipient partner #:sender self-id
                                                                        #:window-size incoming-window #:packet-capacity incoming-capacity))]))])))

(define ssh-chport-filter:confirmation : (-> SSH-Channel-Port SSH-MSG-CHANNEL-OPEN-CONFIRMATION SSH-Configuration Boolean (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc server?]
    (define self-id : Index (ssh:msg:channel:open:confirmation-recipient msg))
    (define partner : Index (ssh:msg:channel:open:confirmation-sender msg))
    (define outgoing-window : Index (ssh:msg:channel:open:confirmation-window-size msg)) ; uint32 field, never larger than 2^32 - 1;
    (define outgoing-capacity : Index (ssh:msg:channel:open:confirmation-packet-capacity msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let ([app-channel (ssh-spot-channel maybe-chport)])
           (set-ssh-spot-peer-id! maybe-chport partner)
           (set-ssh-spot-outgoing-window! maybe-chport outgoing-window)
           (set-ssh-spot-outgoing-upwindow! maybe-chport outgoing-window)

           (when (< outgoing-capacity (ssh-bstring-length (ssh-spot-parcel maybe-chport)))
             (set-ssh-spot-parcel! maybe-chport (make-bytes (max (- outgoing-capacity ssh-channel-data-fault-tolerance) 0))))
           
           (ssh-channel.notify app-channel msg rfc)
           (box app-channel)))))

(define ssh-chport-filter:request : (-> SSH-Channel-Port SSH-MSG-CHANNEL-REQUEST SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define reply? : Boolean (ssh:msg:channel:request-reply? msg))
    (define self-id : Index (ssh:msg:channel:request-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let ([partner (ssh-spot-peer-id maybe-chport)])
           (and partner
                (let ([okay? (ssh-channel.response (ssh-spot-channel maybe-chport) msg rfc)])
                  (and reply?
                       (if (not okay?)
                           (make-ssh:msg:channel:failure #:recipient partner)
                           (make-ssh:msg:channel:success #:recipient partner)))))))))

(define ssh-chport-filter:success : (-> SSH-Channel-Port SSH-MSG-CHANNEL-SUCCESS SSH-Configuration (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:success-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let ([app-channel (ssh-spot-channel maybe-chport)])
           (ssh-channel.notify app-channel msg rfc)
           #false))))

(define ssh-chport-filter:failure : (-> SSH-Channel-Port SSH-MSG-CHANNEL-FAILURE SSH-Configuration (U SSH-Channel-Port-Reply (Boxof Any)))
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:failure-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let ([app-channel (ssh-spot-channel maybe-chport)])
           (ssh-channel.notify app-channel msg rfc)
           #false))))

(define ssh-chport-filter:data : (-> SSH-Channel-Port SSH-MSG-CHANNEL-DATA SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:data-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))

    (and maybe-chport
         (let*-values ([(octets) (ssh:msg:channel:data-payload msg)]
                       [(maybe-partner maybe-adjust) (ssh-chport-check-incoming-parcel! maybe-chport octets)])
           (and maybe-partner
                (let ([feedback (ssh-channel.consume (ssh-spot-channel maybe-chport) octets maybe-partner)])
                  (ssh-chport-update-channel-port! self maybe-chport maybe-adjust)))))))

(define ssh-chport-filter:extended:data : (-> SSH-Channel-Port SSH-MSG-CHANNEL-EXTENDED-DATA SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:extended:data-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let*-values ([(octets) (ssh:msg:channel:extended:data-payload msg)]
                       [(maybe-partner maybe-adjust) (ssh-chport-check-incoming-parcel! maybe-chport octets)])
           (and maybe-partner
                (let ([feedback (ssh-channel.consume (ssh-spot-channel maybe-chport) octets (ssh:msg:channel:extended:data-type msg) maybe-partner)])
                  (ssh-chport-update-channel-port! self maybe-chport feedback maybe-adjust)))))))

(define ssh-chport-filter:window:adjust : (-> SSH-Channel-Port SSH-MSG-CHANNEL-WINDOW-ADJUST SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:window:adjust-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (and msg (hash-ref self self-id (λ [] #false))))
    
    (and maybe-chport
         (ssh-spot-peer-id maybe-chport)
         (let* ([increment (ssh:msg:channel:window:adjust-increment msg)]
                [outgoing-window++ (+ (ssh-spot-outgoing-window maybe-chport) increment)]
                [outgoing-window++ (if (> outgoing-window++ ssh-window-upsize) ssh-window-upsize outgoing-window++)]
                [pending-data (ssh-spot-pending-data maybe-chport)])
           (set-ssh-spot-pending-data! maybe-chport null)
           (set-ssh-spot-outgoing-window! maybe-chport outgoing-window++)
           (set-ssh-spot-outgoing-upwindow! maybe-chport outgoing-window++)
           (ssh-log-message 'debug "~a: the outgoing window is incremented to ~a after ~a consumed"
                            (ssh-channel-name (ssh-spot-channel maybe-chport)) (~size outgoing-window++)
                            (~size (ssh-spot-outgoing-traffic maybe-chport)))
           (ssh-chport-check-outgoing-parcels! self maybe-chport pending-data self-id)))))

(define ssh-chport-filter:eof : (-> SSH-Channel-Port SSH-MSG-CHANNEL-EOF SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:eof-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
  
    (and maybe-chport
         (let ([partner (ssh-channel-incoming-partner maybe-chport)])
           (and partner
                (let ([feedback (ssh-channel.consume (ssh-spot-channel maybe-chport) eof partner)])
                  (set-ssh-spot-incoming-eof?! maybe-chport #true)
                  (ssh-chport-update-channel-port! self maybe-chport feedback)))))))

(define ssh-chport-filter:close : (-> SSH-Channel-Port SSH-MSG-CHANNEL-CLOSE SSH-Configuration SSH-Channel-Port-Reply)
  (lambda [self msg rfc]
    (define self-id : Index (ssh:msg:channel:close-recipient msg))
    (define maybe-chport : (Option SSH-Spot) (hash-ref self self-id (λ [] #false)))
    
    (and maybe-chport
         (let ([channel (ssh-spot-channel maybe-chport)]
               [partner (ssh-spot-peer-id maybe-chport)])
           (hash-remove! self self-id)
           (ssh-channel.destruct channel)
           
           (and partner (make-ssh:msg:channel:close #:recipient partner))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-chport-wrap-evt : (-> SSH-Channel-Port (Evtof SSH-Channel-Reply) SSH-Spot (Evtof SSH-Channel-Port-Reply))
  (lambda [self evt chport]
    (wrap-evt evt
              (λ [[chply : SSH-Channel-Reply]] : SSH-Channel-Port-Reply
                (ssh-chport-update-channel-port! self chport chply)))))

(define ssh-chport-update-channel-port! : (->* (SSH-Channel-Port SSH-Spot SSH-Channel-Reply) ((Option SSH-Message)) SSH-Channel-Reply)
  (lambda [self chport reply [maybe-adjust #false]]
    (let ([replies (ssh-chport-check-outgoing-parcels! self chport reply (ssh-spot-self-id chport))])
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
    
    (cond [(and close?) (set-ssh-spot-peer-id! chport #false)]
          [(pair? pending-data) (set-ssh-spot-pending-data! chport (append (ssh-spot-pending-data chport) pending-data))])
    
    outgoing-replies))

(define ssh-chport-check-outgoing-parcel! : (-> SSH-Spot SSH-Message (Values (Option SSH-Message) (Listof SSH-Message) Boolean))
  (lambda [chport reply]
    (define self-name : Symbol (ssh-channel-name (ssh-spot-channel chport)))
    (define octets : (U Bytes Void)
      (cond [(ssh:msg:channel:data? reply) (ssh:msg:channel:data-payload reply)]
            [(ssh:msg:channel:extended:data? reply) (ssh:msg:channel:extended:data-payload reply)]))

    (cond [(void? octets)
           (values reply null (ssh:msg:channel:close? reply))]
          [(ssh-spot-outgoing-eof? chport)
           (ssh-log-message 'warning "~a: outgoing pipe has been closed" self-name)
           (values #false null #false)]
          [else (let* ([traffic (ssh-bstring-length octets)]
                       [outgoing-window (ssh-spot-outgoing-window chport)]
                       [outgoing-window-- (- outgoing-window traffic)])
                  ; the outgoing traffic always less than the channel capacity by implementation
                  (cond [(not (index? outgoing-window--))
                         (ssh-log-message 'warning "~a: outgoing outgoing window has to be adjusted: ~a < ~a" self-name
                                          (~size outgoing-window #:precision '(= 6)) (~size traffic))
                         (values #false (list reply) #false)]
                        [else (let ([outgoing-traffic++ (+ (ssh-spot-outgoing-traffic chport) traffic)]
                                    [consumption (- (ssh-spot-outgoing-upwindow chport) outgoing-window--)])
                                (set-ssh-spot-outgoing-window! chport outgoing-window--)
                                (set-ssh-spot-outgoing-traffic! chport outgoing-traffic++)
                                (ssh-log-message 'debug "~a: the outgoing window will be decremented to ~a by ~a" self-name
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
    (define self-name : Symbol (ssh-channel-name (ssh-spot-channel chport)))
    
    (cond [(not partner)
           (ssh-log-message 'warning "~a: incoming pipe has been closed" self-name)
           (values #false #false)]
          [(> traffic (+ channel-capacity ssh-channel-data-fault-tolerance))
           (ssh-log-message 'warning "~a: packet is too big: ~a > ~a" self-name (~size traffic) (~size channel-capacity))
           (values #false #false)]
          [(not (index? incoming-window--))
           (ssh-log-message 'warning "~a: the incoming window is too small: ~a < ~a" self-name (~size incoming-window #:precision '(= 6)) (~size traffic))
           (values #false #false)]
          [else (let ([consumption (- incoming-upwindow incoming-window--)])
                  ; see `channel-check-window` in channels.c of OpenSSH
                  (set-ssh-spot-incoming-traffic! chport (+ (ssh-spot-incoming-traffic chport) traffic))
                  (if (and (< incoming-window-- (* channel-capacity 2)) (index? consumption))
                      (let ([incoming-str (~size incoming-upwindow)])
                        (set-ssh-spot-incoming-window! chport incoming-upwindow)
                        (ssh-log-message 'debug "~a: the incoming window is incremented to ~a after ~a consumed"
                                         self-name incoming-str (~size (ssh-spot-incoming-traffic chport)))
                        (values partner (make-ssh:msg:channel:window:adjust #:recipient partner #:increment consumption)))
                      (let ([incoming-str (~size incoming-window-- #:precision '(= 6))])
                        (set-ssh-spot-incoming-window! chport incoming-window--)
                        (ssh-log-message 'debug "~a: the incoming window is decremented to ~a by ~a"
                                         self-name incoming-str (~size consumption))
                        (values partner #false))))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-incoming-partner : (-> SSH-Spot (Option Index))
  (lambda [self]
    (and (not (ssh-spot-incoming-eof? self))
         (ssh-spot-peer-id self))))
