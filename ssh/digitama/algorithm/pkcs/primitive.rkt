#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/number-theory)

(require racket/unsafe/ops)
(require typed/racket/unsafe)

(require "key.rkt")

(unsafe-require/typed
 racket/base
 [ceiling (-> Nonnegative-Exact-Rational Index)])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-integer->octets : (-> Natural Index Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-4.1
  (lambda [x xLen]
    (define X : Bytes (make-bytes xLen #x00))
    (let I2OSP ([idx : Fixnum (- xLen 1)]
                [x : Natural x])
      (when (>= idx 0)
        (unsafe-bytes-set! X idx (bitwise-and x #xFF))
        (I2OSP (- idx 1) (arithmetic-shift x -8))))
    X))

(define pkcs#1-octets->integer : (-> Bytes Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-4.2
  (lambda [X]
    (define xLen : Index (bytes-length X))
    (let OS2IP ([i : Nonnegative-Fixnum 0]
                [x : Natural 0])
      (cond [(>= i xLen) x]
            [else (OS2IP (+ i 1)
                         (+ (arithmetic-shift x 8)
                            (unsafe-bytes-ref X i)))]))))

(define pkcs#1-rsa-sign : (-> RSA-Private Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [K m]
    (modular-expt m (rsa-private-d K) (rsa-private-n K))))

(define pkcs#1-rsa-verify : (-> RSA-Public Natural Natural)
  ;; https://tools.ietf.org/html/rfc8017#section-5.2.1
  (lambda [K s]
    (modular-expt s (rsa-public-e K) (rsa-public-n K))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define octets-length : (-> Natural Index)
  (lambda [bits]
    (ceiling (/ bits 8))))
