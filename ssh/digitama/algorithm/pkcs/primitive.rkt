#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out) bits-bytes-length)

(require math/number-theory)

(require digimon/number)

(require "key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-integer->octets : (-> Natural Index Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-4.1
  (lambda [x xLen]
    (natural->network-bytes x xLen)))

(define pkcs#1-octets->integer : (->* (Bytes) (Natural Natural) Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-4.2
  (lambda [X [start 0] [end0 0]]
    (network-bytes->natural X start end0)))

(define pkcs#1-rsa-sign : (-> RSA-Private Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [K m]
    (modular-expt m (rsa-private-d K) (rsa-key-n K))))

(define pkcs#1-rsa-verify : (-> Natural Natural Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [n e s]
    (modular-expt s e n)))
