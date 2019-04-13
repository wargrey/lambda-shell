#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

(struct ssh-trans-algorithms
  ([cipher : (Pairof Symbol SSH-Cipher)]
   [mac : (Pairof Symbol SSH-HMAC)]
   [compression : (Pairof Symbol SSH-Compression)])
  #:transparent
  #:type-name SSH-Trans-Algorithms)

(struct ssh-kex-newkeys
  ([exchange-hash : Bytes]
   [c2s-initialization-vector : Bytes]
   [s2c-initialization-vector : Bytes]
   [c2s-encryption-key : Bytes]
   [s2c-encryption-key : Bytes]
   [c2s-integrity-key : Bytes]
   [s2c-integrity-key : Bytes])
  #:transparent
  #:type-name SSH-Kex-Newkeys)
