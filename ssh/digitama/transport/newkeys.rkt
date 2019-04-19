#lang typed/racket/base

(provide (all-defined-out))

(struct ssh-newkeys
  ([session-id : Bytes]
   [ciphertext-pool : Bytes]
   [plaintext-pool : Bytes]
   [inflate : (Option (-> Bytes Bytes))]
   [deflate : (Option (-> Bytes Bytes))]
   [encrypt : (->* (Bytes) ((Option Bytes)) (Values Bytes Index))]
   [decrypt : (->* (Bytes) ((Option Bytes)) (Values Bytes Index))]
   [encrypt-block-size : Byte]
   [decrypt-block-size : Byte]
   [mac-generate : (-> Bytes Bytes)]
   [mac-verify : (-> Bytes Bytes)])
  #:transparent
  #:type-name SSH-Newkeys)
