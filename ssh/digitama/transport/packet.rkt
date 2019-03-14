#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

(define SSH-LONGEST-PACKET-LENGTH : Positive-Index 35000)

(struct SSH-Packet
  ([length : Positive-Index]
   [padding-length : Positive-Index]
   [payload : Bytes]
   [random-padding : Bytes]
   [mac : Bytes]))

#;(define read-binary-packet : (-> Input-Port SSH-Packet)
  (lambda [/dev/sshin]
    payload))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-binary-packet : (-> Bytes Positive-Byte Bytes)
  (lambda [payload cipher-block-size]
    payload))
