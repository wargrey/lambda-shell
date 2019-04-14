#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

(struct ssh-kex-newkeys
  ([exchange-hash : Bytes]
   [c2s-initialization-vector : Bytes]
   [s2c-initialization-vector : Bytes]
   [c2s-encryption-key : Bytes]
   [s2c-encryption-key : Bytes]
   [c2s-integrity-key : Bytes]
   [s2c-integrity-key : Bytes]
   [c2s-compression : SSH-Compression]
   [s2c-compression : SSH-Compression]
   [c2s-cipher : SSH-Cipher]
   [s2c-cipher : SSH-Cipher]
   [c2s-mac : SSH-MAC]
   [s2c-mac : SSH-MAC])
  #:transparent
  #:type-name SSH-Kex-Newkeys)
