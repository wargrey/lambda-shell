#lang typed/racket/base

(provide (all-defined-out))

(struct ssh-newkeys
  ([session-id : Bytes]
   [packet-pool : Bytes]
   [inflate : (Option (-> Bytes Bytes))]
   [deflate : (Option (-> Bytes Bytes))]
   [encrypt : (->* (Bytes) (Index Index (Option Bytes) Index Index) Index)]
   [decrypt : (->* (Bytes) (Index Index (Option Bytes) Index Index) Index)]
   [encrypt-block-size : Byte]
   [decrypt-block-size : Byte]
   [mac-generate : (-> Bytes Bytes)]
   [mac-verify : (-> Bytes Bytes)])
  #:transparent
  #:type-name SSH-Newkeys)
