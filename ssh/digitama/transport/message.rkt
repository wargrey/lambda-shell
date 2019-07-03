#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "packet.rkt")
(require "newkeys.rkt")

(require "../diagnostics.rkt")

(require "../../message.rkt")
(require "../../configuration.rkt")

(require "../message/transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-message : (-> Output-Port SSH-Message SSH-Configuration Maybe-Newkeys Natural)
  (lambda [/dev/tcpout msg rfc newkeys]
    (define payload-length : Natural (ssh-message-length msg))
    (define outgoing-parcel : Bytes (ssh-parcel-outgoing (if (ssh-parcel? newkeys) newkeys (ssh-newkeys-parcel newkeys))))
    (define maybe-overload-parcel : (Option Bytes)
      (and (not (ssh-check-outgoing-payload-size payload-length ($ssh-payload-capacity rfc)))
           (let ([overload-parcel (make-bytes (ssh-parcel-assess-size payload-length))])
             (bytes-copy! overload-parcel 0 outgoing-parcel 0 ssh-packet-size-index)
             overload-parcel)))

    (define traffic : Nonnegative-Fixnum
      (let ([parcel (or maybe-overload-parcel outgoing-parcel)])
        (ssh-message->bytes msg parcel ssh-packet-payload-index)
        (cond [(ssh-parcel? newkeys) (ssh-write-plain-packet /dev/tcpout parcel payload-length ($ssh-pretty-log-packet-level rfc))]
              [else (ssh-write-cipher-packet /dev/tcpout parcel payload-length (ssh-newkeys-inflate newkeys)
                                             (ssh-newkeys-encrypt newkeys) (ssh-newkeys-encrypt-block-size newkeys) (ssh-newkeys-mac-generate newkeys)
                                             ($ssh-pretty-log-packet-level rfc))])))

    (unless (not maybe-overload-parcel)
      ; the new sequence number is required
      ; the content of the overload parcel can also be used as the 'random' padding for following message 
      (bytes-copy! outgoing-parcel 0 maybe-overload-parcel 0 (bytes-length outgoing-parcel)))
    
    (ssh-log-message 'debug "sent message ~a[~a] (~a)" (ssh-message-name msg) (ssh-message-number msg) (~size traffic))
    (ssh-log-outgoing-message msg 'debug)

    (when (ssh:msg:disconnect? msg)
      (ssh-suicide ssh-write-message msg))

    traffic))

(define ssh-read-transport-message : (-> Input-Port SSH-Configuration Maybe-Newkeys (Option Symbol) (Values (Option SSH-Message) Bytes Natural))
  (lambda [/dev/tcpin rfc newkeys group]
    (define incoming-parcel : Bytes (ssh-parcel-incoming (if (ssh-parcel? newkeys) newkeys (ssh-newkeys-parcel newkeys))))
    (define-values (payload-end traffic)
      (cond [(ssh-parcel? newkeys) (ssh-read-plain-packet /dev/tcpin incoming-parcel ($ssh-payload-capacity rfc) ($ssh-pretty-log-packet-level rfc))]
            [else (ssh-read-cipher-packet /dev/tcpin (ssh-parcel-incoming (ssh-newkeys-parcel newkeys))
                                          ($ssh-payload-capacity rfc) (ssh-newkeys-decrypt-block-size newkeys)
                                          (ssh-newkeys-deflate newkeys) (ssh-newkeys-decrypt newkeys) (ssh-newkeys-mac-verify newkeys)
                                          ($ssh-pretty-log-packet-level rfc))]))
    
    (define message-id : Byte (ssh-message-payload-number incoming-parcel ssh-packet-payload-index))
    (define-values (maybe-trans-msg _) (ssh-bytes->transport-message incoming-parcel ssh-packet-payload-index #:group group))

    (cond [(not maybe-trans-msg) (ssh-log-message 'debug "received message ~a (~a)" message-id (~size traffic))]
          [else (ssh-log-message 'debug "received transport layer message ~a[~a] (~a)"
                                 (ssh-message-name maybe-trans-msg) message-id (~size traffic))])
    
    (unless (not maybe-trans-msg)
      (ssh-log-incoming-message maybe-trans-msg 'debug)

      (cond [(ssh:msg:debug? maybe-trans-msg)
             (($ssh-debug-message-handler rfc)
              (ssh:msg:debug-display? maybe-trans-msg) (ssh:msg:debug-message maybe-trans-msg) (ssh:msg:debug-language maybe-trans-msg))]
            [(ssh:msg:disconnect? maybe-trans-msg)
             (ssh-suicide ssh-read-transport-message maybe-trans-msg)]))

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

(define ssh-log-outgoing-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:debug? msg)
           (when (ssh:msg:debug-display? msg)
             (ssh-log-message level "[DEBUG] ~a" (ssh:msg:debug-message msg) #:with-peer-name? #false))]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "terminate the connection ~a because of ~a, details: ~a"
                            (current-peer-name) (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "cannot not deal with message ~a from ~a"
                            (ssh:msg:unimplemented-number msg) (current-peer-name))]
          [(ssh:msg:service:request? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "request service '~a' from ~a"
                            (ssh:msg:service:request-name msg) (current-peer-name))]
          [(ssh:msg:service:accept? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "service '~a' is available to ~a"
                            (ssh:msg:service:accept-name msg) (current-peer-name))])))

(define ssh-log-incoming-message : (->* (SSH-Message) (Log-Level) Void)
  (lambda [msg [level 'debug]]
    (cond [(ssh:msg:debug? msg)
           (when (ssh:msg:debug-display? msg)
             (ssh-log-message level "[DEBUG] ~a says: ~a" (current-peer-name) (ssh:msg:debug-message msg) #:with-peer-name? #false))]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "~a has disconnected with the reason ~a(~a)" (current-peer-name)
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "~a cannot deal with message ~a"
                            (current-peer-name) (ssh:msg:unimplemented-number msg))]
          [(ssh:msg:service:request? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "~a requests the service '~a'"
                            (current-peer-name) (ssh:msg:service:request-name msg))]
          [(ssh:msg:service:accept? msg)
           (ssh-log-message #:with-peer-name? #false
                            level "~a accepts the request for service '~a'"
                            (current-peer-name) (ssh:msg:service:accept-name msg))])))

(define ssh-suicide : (-> Procedure SSH-MSG-DISCONNECT Nothing)
  (lambda [func msg]
    (ssh-raise-eof-error func (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg)
                         #:logging? #false)))
