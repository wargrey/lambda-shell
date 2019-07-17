#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "packet.rkt")
(require "newkeys.rkt")
(require "prompt.rkt")

(require "../message.rkt")
(require "../diagnostics.rkt")

(require "../assignment/message.rkt")
(require "../message/transport.rkt")

(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-plain-message : (-> Output-Port SSH-Message SSH-Configuration SSH-Parcel Natural)
  (lambda [/dev/tcpout msg rfc parcel]
    (define time0 : Flonum (current-inexact-milliseconds))
    (define payload-length : Natural (ssh-message-length msg))
    (define outgoing-parcel : Bytes (ssh-parcel-outgoing parcel))
    (define maybe-overload-parcel : (Option Bytes) (ssh-pre-write-message outgoing-parcel payload-length rfc (ssh-parcel-mac-capacity parcel)))

    (define traffic : Nonnegative-Fixnum
      (let ([parcel (or maybe-overload-parcel outgoing-parcel)])
        (ssh-message->bytes msg parcel ssh-packet-payload-index)
        (ssh-write-plain-packet /dev/tcpout parcel payload-length ($ssh-pretty-log-packet-level rfc))))
    
    (ssh-post-write-message outgoing-parcel msg traffic time0 maybe-overload-parcel)))

(define ssh-read-plain-transport-message : (-> Input-Port SSH-Configuration SSH-Parcel (Option Symbol) (Values (Option SSH-Message) Bytes Natural))
  (lambda [/dev/tcpin rfc parcel group]
    (define time0 : Flonum (current-inexact-milliseconds))
    (define incoming : Bytes (ssh-parcel-incoming parcel))
    (define-values (payload-end traffic)
      (ssh-read-plain-packet /dev/tcpin incoming ($ssh-payload-capacity rfc) ssh-parcel-fault-tolerance-size ($ssh-pretty-log-packet-level rfc)))
    
    (ssh-post-read-transport-message incoming payload-end traffic time0 rfc group)))

(define ssh-write-cipher-message : (-> Output-Port SSH-Message SSH-Configuration SSH-Newkeys Natural)
  (lambda [/dev/tcpout msg rfc newkeys]
    (define time0 : Flonum (current-inexact-milliseconds))
    (define parcel : SSH-Parcel (ssh-newkeys-parcel newkeys))
    (define payload-length : Natural (ssh-message-length msg))
    (define outgoing-parcel : Bytes (ssh-parcel-outgoing parcel))
    (define maybe-overload-parcel : (Option Bytes) (ssh-pre-write-message outgoing-parcel payload-length rfc (ssh-parcel-mac-capacity parcel)))

    (define traffic : Nonnegative-Fixnum
      (let ([parcel (or maybe-overload-parcel outgoing-parcel)])
        (ssh-message->bytes msg parcel ssh-packet-payload-index)
        (ssh-write-cipher-packet /dev/tcpout parcel payload-length (ssh-newkeys-inflate newkeys)
                                 (ssh-newkeys-encrypt newkeys) (ssh-newkeys-encrypt-block-size newkeys) (ssh-newkeys-mac-generate newkeys)
                                 ($ssh-pretty-log-packet-level rfc))))

    (ssh-post-write-message outgoing-parcel msg traffic time0 maybe-overload-parcel)))

(define ssh-read-cipher-transport-message : (-> Input-Port SSH-Configuration SSH-Newkeys (Option Symbol) (Values (Option SSH-Message) Bytes Natural))
  (lambda [/dev/tcpin rfc newkeys group]
    (define time0 : Flonum (current-inexact-milliseconds))
    (define incoming : Bytes (ssh-parcel-incoming (ssh-newkeys-parcel newkeys)))
    (define-values (payload-end traffic)
      (ssh-read-cipher-packet /dev/tcpin incoming
                              ($ssh-payload-capacity rfc) ssh-parcel-fault-tolerance-size (ssh-newkeys-decrypt-block-size newkeys)
                              (ssh-newkeys-deflate newkeys) (ssh-newkeys-decrypt newkeys) (ssh-newkeys-mac-verify newkeys)
                              ($ssh-pretty-log-packet-level rfc)))
    
    (ssh-post-read-transport-message incoming payload-end traffic time0 rfc group)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-pre-write-message : (-> Bytes Natural SSH-Configuration Index (Option Bytes))
  (lambda [outgoing-parcel payload-length rfc mac-capacity]
    (define maybe-overload-parcel : (Option Bytes)
      (and (not (ssh-check-outgoing-payload-size payload-length ($ssh-payload-capacity rfc) ssh-parcel-fault-tolerance-size))
           (let ([overload-parcel (make-bytes (ssh-parcel-assess-size payload-length mac-capacity))])
             (bytes-copy! overload-parcel 0 outgoing-parcel 0 ssh-packet-size-index)
             overload-parcel)))
    
    maybe-overload-parcel))

(define ssh-post-write-message : (-> Bytes SSH-Message Nonnegative-Fixnum Flonum (Option Bytes) Nonnegative-Fixnum)
  (lambda [outgoing-parcel msg traffic time0 maybe-overloaded-parcel]
    (unless (not maybe-overloaded-parcel)
      ; the new sequence number is required
      ; the content of the overload parcel can also be used as the 'random' padding for following message 
      (bytes-copy! outgoing-parcel 0 maybe-overloaded-parcel 0 (bytes-length outgoing-parcel)))

    (let* ([timespan (- (current-inexact-milliseconds) time0)])
      (ssh-log-message 'debug "sent message ~a[~a] (~a, ~ams)" (ssh-message-name msg) (ssh-message-number msg)
                       (~size traffic #:precision 3) (~r timespan #:precision 6)))
    
    (ssh-log-outgoing-message msg)

    (when (ssh:msg:disconnect? msg)
      (ssh-collapse msg))

    traffic))

(define ssh-post-read-transport-message : (-> Bytes Positive-Fixnum Nonnegative-Fixnum Flonum SSH-Configuration (Option Symbol)
                                              (Values (Option SSH-Message) Bytes Nonnegative-Fixnum))
  (lambda [incoming-parcel payload-end traffic time0 rfc group]
    (define msg-id : Byte (ssh-message-payload-number incoming-parcel ssh-packet-payload-index))
    (define-values (maybe-trans-msg _) (ssh-bytes->transport-message incoming-parcel ssh-packet-payload-index #:group group))
    (define clocktime : Flonum (- (current-inexact-milliseconds) time0))
    (define strtime : String (~r clocktime #:precision '(= 6)))

    (let* ([timespan (- (current-inexact-milliseconds) time0)]
           [ms (~r timespan #:precision 6)])
      (cond [(not maybe-trans-msg) (ssh-log-message 'debug "received message ~a (~a, ~ams)" msg-id (~size traffic #:precision 3) ms)]
            [else (ssh-log-message 'debug "received transport layer message ~a[~a] (~a, ~ams)" (ssh-message-name maybe-trans-msg) msg-id
                                   (~size traffic #:precision 3) ms)]))
    
    (unless (not maybe-trans-msg)
      (ssh-log-incoming-message maybe-trans-msg)

      (cond [(ssh:msg:debug? maybe-trans-msg)
             (($ssh-debug-message-handler rfc)
              (ssh:msg:debug-display? maybe-trans-msg) (ssh:msg:debug-message maybe-trans-msg) (ssh:msg:debug-language maybe-trans-msg))]
            [(ssh:msg:disconnect? maybe-trans-msg)
             (ssh-collapse maybe-trans-msg)]))

    (values maybe-trans-msg
            (cond [(and maybe-trans-msg (not (ssh:msg:kexinit? maybe-trans-msg))) #"" #| useless but to satisfy the type system |#]
                  [else (subbytes incoming-parcel ssh-packet-payload-index payload-end)])
            traffic)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex-transparent-message? : (-> SSH-Message Boolean)
  (lambda [msg]
    (and (ssh-transport-message? msg)
         (not (or (ssh:msg:service:request? msg)
                  (ssh:msg:service:accept? msg)
                  (ssh:msg:kexinit? msg))))))

(define ssh-ignored-incoming-message? : (-> SSH-Message Boolean)
  (lambda [msg]
    (or (ssh:msg:ignore? msg)
        (ssh:msg:debug? msg)
        (ssh:msg:unimplemented? msg))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-kexinit : (->* (SSH-MSG-KEXINIT String) (Log-Level) Void)
  (lambda [msg prefix [level 'debug]]
    (ssh-log-message level "~a KEX algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-kexes msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a host key algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-hostkeys msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a c2s encryption algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-ciphers msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a s2c encryption algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-ciphers msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a c2s MAC algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-macs msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a s2c MAC algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-macs msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a c2s compression algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-compressions msg)) #:with-peer-name? #false)
    (ssh-log-message level "~a s2c compression algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-compressions msg)) #:with-peer-name? #false)))

(define ssh-log-outgoing-message : (-> SSH-Message Void)
  (lambda [msg]
    (cond [(ssh:msg:debug? msg)
           (ssh-log-message 'debug "[DEBUG] ~a" (ssh:msg:debug-message msg) #:with-peer-name? #false)]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "terminate the connection ~a because of ~a, details: ~a"
                            (current-peer-name) (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message #:with-peer-name? #false
                            'debug "cannot not deal with message ~a from ~a"
                            (ssh:msg:unimplemented-number msg) (current-peer-name))]
          [(ssh:msg:service:request? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "request service '~a' provided by ~a"
                            (ssh:msg:service:request-name msg) (current-peer-name))]
          [(ssh:msg:service:accept? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "service '~a' is available to ~a"
                            (ssh:msg:service:accept-name msg) (current-peer-name))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:debug? msg)
           (ssh-log-message 'info "[DEBUG] ~a says: ~a" (current-peer-name) (ssh:msg:debug-message msg) #:with-peer-name? #false)]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "~a has disconnected with the reason ~a(~a)" (current-peer-name)
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message #:with-peer-name? #false
                            'debug "~a cannot deal with message ~a"
                            (current-peer-name) (ssh:msg:unimplemented-number msg))]
          [(ssh:msg:service:request? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "~a requests the service '~a'"
                            (current-peer-name) (ssh:msg:service:request-name msg))]
          [(ssh:msg:service:accept? msg)
           (ssh-log-message #:with-peer-name? #false
                            'info "~a accepts the request for service '~a'"
                            (current-peer-name) (ssh:msg:service:accept-name msg))])))

(define ssh-transport-MB/s : (-> Nonnegative-Fixnum Flonum Flonum)
  (lambda [traffic timespan]
    (/ (real->double-flonum traffic)
       (* timespan 1024.0 1.024))))
