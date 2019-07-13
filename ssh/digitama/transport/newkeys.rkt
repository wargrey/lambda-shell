#lang typed/racket/base

(provide (all-defined-out))

#| parcel
 uint32    packet_sequence_number ([0, #xFFFFFFFF], never reset, cyclic, not sent over the wire)
 byte[n]   packet body (n = maximum packet_length, plaintext and/or ciphertext)
 byte[m]   packet mac (m = mac_length)
 byte[t]   packet fault tolerance
|#

(define-type Maybe-Newkeys (U SSH-Parcel SSH-Newkeys))

(struct ssh-parcel
  ([incoming : Bytes]
   [outgoing : Bytes]
   [mac-capacity : Index])
  #:type-name SSH-Parcel)

(struct ssh-newkeys
  ([identity : Bytes]
   [parcel : SSH-Parcel]
   [inflate : (Option (->* (Bytes) (Natural Natural) Bytes))]
   [deflate : (Option (->* (Bytes) (Natural Natural) Bytes))]
   [encrypt : (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)]
   [decrypt : (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)]
   [encrypt-block-size : Byte]
   [decrypt-block-size : Byte]
   [mac-generate : (->* (Bytes) (Natural Natural) Bytes)]
   [mac-verify : (->* (Bytes) (Natural Natural) Bytes)])
  #:type-name SSH-Newkeys
  #:transparent)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; NOTE
; The fault tolerance size is designed for SSH-MSG-CHANNEL-DATA and SSH-MSG-CHANNEL-EXTENDED-DATA.
;
; RFC4254 does not make it clear that whether the 'maximum packet size' specifies the maximum size of
;   the SSH-MSG-CHANNEL-DATA/SSH-MSG-CHANNEL-EXTENDED-DATA messages(a.k.a the payload of packet from
;   the perspective of transport layer) or just the maximum size of the data carried by messages of
;   those two kinds.
;
; It seems that OpenSSH interpretes it as the channel data capacity (with uint32 length).
(define ssh-parcel-fault-tolerance-size : Byte 16)

(define ssh-parcel-assess-size : (-> Natural Index Natural)
  (lambda [payload-capacity mac-length]
    (+ 4
       4 1 payload-capacity #xFF
       mac-length
       ssh-parcel-fault-tolerance-size)))

(define make-ssh-parcel : (->* (Index Index) (Nonnegative-Fixnum) SSH-Parcel)
  (lambda [payload-capacity mac-length [sequence-start 0]]
    (define parcel-size : Natural (ssh-parcel-assess-size payload-capacity mac-length))
    (define outgoing : Bytes (make-bytes parcel-size))
    (define incoming : Bytes (make-bytes parcel-size))

    (integer->integer-bytes sequence-start 4 #false #true outgoing 0)
    (integer->integer-bytes sequence-start 4 #false #true incoming 0)

    ; TODO: if random parcels are needed?
    
    (ssh-parcel incoming outgoing mac-length)))

(define ssh-parcel-action-on-rekexed : (-> SSH-Parcel Void)
  (lambda [self]
    (void '(do nothing))))
