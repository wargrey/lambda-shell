#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/number-theory)

(require "key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-integer->octets : (-> Integer Index Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-4.1
  (lambda [x xLen]
    (define X : Bytes (make-bytes xLen #x00))
    
    (let I2OSP ([sth : Nonnegative-Fixnum xLen]
                [x : Integer x])
      (define sth-8 : Fixnum (- sth 8))
      (define sth-4 : Fixnum (- sth 4))
      (define sth-1 : Fixnum (- sth 1))
      
      (cond [(>= sth-8 0)
             (integer->integer-bytes (bitwise-and x #xFFFFFFFFFFFFFFFF) 8 #false #true X sth-8)
             (I2OSP sth-8 (arithmetic-shift x -64))]
            [(>= sth-4 0)
             (integer->integer-bytes (bitwise-and x #xFFFFFFFF) 4 #false #true X sth-4)
             (I2OSP sth-4 (arithmetic-shift x -32))]
            [(>= sth-1 0)
             (bytes-set! X sth-1 (bitwise-and x #xFF))
             (I2OSP sth-1 (arithmetic-shift x -8))]))
    
    X))

(define pkcs#1-octets->integer : (->* (Bytes) (Natural Natural) Integer)
  ;; https://tools.ietf.org/html/rfc8017#section-4.2
  (lambda [X [start 0] [end0 0]]
    (define end : Index (assert (if (<= end0 start) (bytes-length X) end0) index?))

    (let OS2IP ([idx : Index (assert start index?)]
                [x : Integer (if (>= (bytes-ref X start) #b10000000) -1 0)])
      (define idx+8 : Nonnegative-Fixnum (+ idx 8))
      (define idx+4 : Nonnegative-Fixnum (+ idx 4))
      (define idx+1 : Nonnegative-Fixnum (+ idx 1))
      
      (cond [(<= idx+8 end) (OS2IP idx+8 (bitwise-ior (arithmetic-shift x 64) (integer-bytes->integer X #false #true idx idx+8)))]
            [(<= idx+4 end) (OS2IP idx+4 (bitwise-ior (arithmetic-shift x 32) (integer-bytes->integer X #false #true idx idx+4)))]
            [(<= idx+1 end) (OS2IP idx+1 (bitwise-ior (arithmetic-shift x 8) (bytes-ref X idx)))]
            [else x]))))

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
