#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")
(require "algorithm/pkcs1/hash.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Hostkey-Constructor (-> PKCS#1-Hash SSH-Hostkey))

(define-type SSH-Hostkey-Make-Public-Key (-> SSH-Hostkey Bytes))
(define-type SSH-Hostkey-Sign (-> SSH-Hostkey Bytes Bytes))

(struct ssh-hostkey
  ([name : Symbol]
   [hash : PKCS#1-Hash]
   [make-public-key : SSH-Hostkey-Make-Public-Key]
   [sign : SSH-Hostkey-Sign])
  #:type-name SSH-Hostkey)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Kex-Constructor (-> String String Bytes Bytes SSH-Hostkey (-> Bytes Bytes) SSH-Kex))

(define-type SSH-Kex-Request (-> SSH-Kex SSH-Message))
(define-type SSH-Kex-Response (-> SSH-Kex SSH-Message (Option SSH-Message)))
(define-type SSH-Kex-Done? (-> SSH-Kex Boolean))

(struct ssh-kex
  ([name : Symbol]
   [hostkey : SSH-Hostkey]
   [hash : (-> Bytes Bytes)]
   [K : (Boxof Integer)]
   [H : (Boxof Bytes)]
   [request : SSH-Kex-Request]
   [response : SSH-Kex-Response]
   [done? : SSH-Kex-Done?])
  #:type-name SSH-Kex)
