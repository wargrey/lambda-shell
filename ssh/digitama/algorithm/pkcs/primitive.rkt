#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/number-theory)

(require racket/unsafe/ops)

(require "key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-integer->octets : (-> Integer Index Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-4.1
  (lambda [x xLen]
    (define X : Bytes (make-bytes xLen #x00))
    (let I2OSP ([idx : Fixnum (- xLen 1)]
                [x : Integer x])
      (when (>= idx 0)
        (unsafe-bytes-set! X idx (bitwise-and x #xFF))
        (I2OSP (- idx 1) (arithmetic-shift x -8))))
    X))

(define pkcs#1-octets->natural : (->* (Bytes) (Natural Natural) Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-4.2
  (lambda [X [start 0] [end0 0]]
    (define end : Index (assert (if (<= end0 start) (bytes-length X) end0) index?))
    (let OS2IP ([i : Natural start]
                [x : Natural 0])
      (cond [(>= i end) x]
            [else (OS2IP (+ i 1)
                         (bitwise-ior (arithmetic-shift x 8)
                                      (bytes-ref X i)))]))))

(define pkcs#1-rsa-sign : (-> RSA-Private Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [K m]
    (modular-expt m (rsa-private-d K) (rsa-key-n K))))

(define pkcs#1-rsa-verify : (-> Natural Natural Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [n e s]
    (modular-expt s e n)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define octets-length : (-> Natural Index)
  (lambda [bits]
    (define-values (q r) (quotient/remainder bits 8))
    (assert (if (= r 0) q (+ q 1)) index?)))
