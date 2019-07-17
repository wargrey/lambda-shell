#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "channel.rkt")

(require "../message.rkt")
(require "../message/connection.rkt")

(require "../diagnostics.rkt")

(require "../../datatype.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-window-upsize : Index (assert (- (expt 2 32) 1) index?))

(struct ssh-channel-port
  ([entity : SSH-Channel]
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
  #:type-name SSH-Channel-Port
  #:mutable)

(define ssh-channel-incoming-partner : (-> SSH-Channel-Port (Option Index))
  (lambda [self]
    (and (not (ssh-channel-port-incoming-eof? self))
         (ssh-channel-port-partner self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-check-outgoing-parcel! : (-> SSH-Channel-Port SSH-Message (Values (Option SSH-Message) (Listof SSH-Message) Boolean))
  (lambda [chport reply]
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
    (define incoming-window : Index (ssh-channel-port-incoming-window chport))
    (define incoming-window-- : Integer (- incoming-window traffic))
    (define channel-capacity : Natural (ssh-bstring-length (ssh-channel-port-parcel chport)))
    (define self-str : String (number->string (ssh-channel-id (ssh-channel-port-entity chport)) 16))
    
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
                  (set-ssh-channel-port-incoming-traffic! chport (+ (ssh-channel-port-incoming-traffic chport) traffic))
                  (if (and (< incoming-window-- (* channel-capacity 2)) (index? consumption))
                      (let ([incoming-str (~size incoming-upwindow)])
                        (set-ssh-channel-port-incoming-window! chport incoming-upwindow)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is incremented to ~a after ~a consumed"
                                         self-str incoming-str (~size (ssh-channel-port-incoming-traffic chport)))
                        (values partner (make-ssh:msg:channel:window:adjust #:recipient partner #:increment consumption)))
                      (let ([incoming-str (~size incoming-window-- #:precision '(= 6))])
                        (set-ssh-channel-port-incoming-window! chport incoming-window--)
                        (ssh-log-message 'debug "Channel[0x~a]: the incoming window is decremented to ~a by ~a"
                                         self-str incoming-str (~size consumption))
                        (values partner #false))))])))


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

