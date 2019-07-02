#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")
(require "algorithm/pkcs1/hash.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Hostkey-Constructor (-> PKCS#1-Hash Positive-Index SSH-Hostkey))

(define-type SSH-Hostkey-Make-Public-Key (-> SSH-Hostkey Bytes))
(define-type SSH-Hostkey-Sign (-> SSH-Hostkey Bytes Bytes))

(define-object ssh-hostkey : SSH-Hostkey
  ([name : Symbol]
   [hash : PKCS#1-Hash])
  ([make-public-key : SSH-Hostkey-Make-Public-Key]
   [sign : SSH-Hostkey-Sign]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Kex-Constructor (-> String String Bytes Bytes SSH-Hostkey (-> Bytes Bytes) Positive-Index SSH-Kex))

(define-type SSH-Kex-Request (-> SSH-Kex (Values SSH-Kex SSH-Message)))
(define-type SSH-Kex-Reply (-> SSH-Kex SSH-Message (Values SSH-Kex (U SSH-Message (Pairof SSH-Message (Pairof Integer Bytes)) False))))
(define-type SSH-Kex-Verify (-> SSH-Kex SSH-Message (Values SSH-Kex (U SSH-Message (Pairof Integer Bytes) False))))

(define-object ssh-kex : SSH-Kex
  ([name : Symbol]
   [hostkey : SSH-Hostkey]
   [hash : (-> Bytes Bytes)])
  ([request : SSH-Kex-Request]
   [reply : SSH-Kex-Reply]
   [verify : SSH-Kex-Verify]))
