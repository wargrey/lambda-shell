#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

(require "../stdin.rkt")
(require "../datatype.rkt")
(require "../exception.rkt")

(define SSH-LONGEST-PACKET-LENGTH : Positive-Index 35000)

(struct SSH-Packet
  ([length : UInt32]
   [padding-length : Byte]
   [payload : Bytes]
   [random-padding : Bytes]
   [mac : Bytes]))

(define read-binary-packet : (-> Input-Port SSH-Packet)
  (lambda [/dev/sshin]
    (define length-bs : Bytes (ssh-read-bytes /dev/sshin 4))
    (define packet-length : UInt32 (ssh-bytes->uint32 length-bs))
    (when (> packet-length SSH-LONGEST-PACKET-LENGTH)
      (throw exn:ssh:defense /dev/sshin 'read-binary-packet
             "packet overlength: ~a" packet-length))
    (define padded-payload : Bytes (ssh-read-bytes /dev/sshin packet-length))
    (define padding-length : Byte (bytes-ref padded-payload 0))
    (define padding-index : Fixnum (- packet-length padding-length))
    (when (< padding-index 1)
      (throw exn:ssh:defense /dev/sshin 'read-binary-packet
             "invalid payload length: ~a" (sub1 padding-index)))
    (SSH-Packet packet-length padding-length
                (subbytes padded-payload 1 padding-index)
                (subbytes padded-payload padding-index)
                #"")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-binary-packet : (-> Bytes Positive-Byte Bytes)
  (lambda [payload cipher-blocksize]
    payload))
