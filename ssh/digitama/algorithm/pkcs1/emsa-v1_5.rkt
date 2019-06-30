#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017
  
(provide (all-defined-out))

(require "key.rkt")
(require "hash.rkt")
(require "primitive.rkt")

(require "../../diagnostics.rkt")

(define rsa-sign : (-> RSA-Private-Key Bytes PKCS#1-Hash Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-8.2.1
  (lambda [key message id-hash]
    (define mbits : Nonnegative-Fixnum (integer-length (rsa-private-key-n key)))
    (define k : Index (bits-bytes-length mbits))
    (define embits : Index (assert (- mbits 1) index?))
    (define em : Bytes (pkcs#1-v1.5-encode message embits (pkcs#1-hash-der id-hash) (pkcs#1-hash-method id-hash) rsa-sign))
    (define m : Natural (assert (pkcs#1-octets->integer em) exact-nonnegative-integer?))
    (define s : Natural (pkcs#1-rsa-sign key m))
    
    (pkcs#1-integer->octets s k)))

(define rsa-verify : (->* ((U RSA-Public-Key RSA-Private-Key) Bytes Bytes PKCS#1-Hash) (Natural Natural) Boolean)
  ;; https://tools.ietf.org/html/rfc8017#section-8.2.2
  (lambda [key message signature id-hash [sig-off 0] [sigend 0]]
    (define-values (modulus public-exponent)
      (cond [(rsa-public-key? key) (values (rsa-public-key-n key) (rsa-public-key-e key))]
            [else (values (rsa-private-key-n key) (rsa-private-key-e key))]))
    
    (define mbits : Nonnegative-Fixnum (integer-length modulus))
    (define k : Index (bits-bytes-length mbits))
    (define sig-end : Natural (if (<= sigend sig-off) (bytes-length signature) sigend))

    (and (= k (- sig-end sig-off))
         (let* ([s (pkcs#1-octets->integer signature sig-off sig-end)]
                [m (pkcs#1-rsa-verify modulus public-exponent s)]
                [embits (assert (- mbits 1) index?)])
           (bytes=? (pkcs#1-v1.5-encode message embits (pkcs#1-hash-der id-hash) (pkcs#1-hash-method id-hash) rsa-verify)
                    (pkcs#1-integer->octets m k))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-v1.5-encode : (-> Bytes Index Bytes (-> Bytes Bytes) Procedure Bytes)
  (let ([0x0001 (bytes #x00 #x01)]
        [0x00 (bytes #x00)])
    (lambda [message embits der-head hash src]
      ; No need to check the max length of message, for SHA-1, it's (2^61 - 1), this limitation is impractical.
      (define emLen : Index (bits-bytes-length embits))
      (define T : Bytes (bytes-append der-head (hash message)))
      (define tLen : Index (bytes-length T))
      (define psLen : Integer (- emLen tLen 3))

      (cond [(byte? psLen) (bytes-append 0x0001 (make-bytes psLen #xFF) 0x00 T)]
            [else (ssh-raise-kex-error src
                                       "intended encoding message length too short (~a < ~a)"
                                       embits (+ tLen 3))]))))
