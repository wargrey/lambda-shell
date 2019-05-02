#lang typed/racket/base

(provide (all-defined-out))

#| parcel
 uint32    packet_sequence_number ([0, #xFFFFFFFF], never reset, cyclic, not sent over the wire)
 byte[n]   packet body (n = maximum packet_length, plaintext and/or ciphertext)
 byte[m]   packet mac (m = mac_length)
|#

(define-type Maybe-Newkeys (U SSH-Parcel SSH-Newkeys))

(struct ssh-parcel
  ([incoming : Bytes]
   [outgoing : Bytes])
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
  #:transparent
  #:type-name SSH-Newkeys)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-parcel-assess-size : (-> Natural Natural)
  (lambda [payload-capacity]
    (+ 4
       4 1 payload-capacity
       #xFF)))

(define make-ssh-parcel : (->* (Index) (Nonnegative-Fixnum) SSH-Parcel)
  (lambda [payload-capacity [sequence-start 0]]
    (define parcel-size : Natural (ssh-parcel-assess-size payload-capacity))
    (define outgoing : Bytes (make-bytes parcel-size))
    (define incoming : Bytes (make-bytes parcel-size))

    (integer->integer-bytes sequence-start 4 #false #true outgoing 0)
    (integer->integer-bytes sequence-start 4 #false #true incoming 0)

    ; TODO: if random parcels are needed?
    
    (ssh-parcel incoming outgoing)))

(define ssh-parcel-action-on-rekexed : (-> SSH-Parcel Void)
  (lambda [self]
    (void '(do nothing))))
