#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017
  
(provide (all-defined-out))

(require "key.rkt")
(require "hash.rkt")
(require "primitive.rkt")

(require "../../diagnostics.rkt")

(define rsa-sign : (-> RSA-Private Bytes PKCS#1-Hash Symbol Bytes)
  ;; https://tools.ietf.org/html/rfc8017#section-8.2.1
  (lambda [key message id-hash peer-name]
    (define mbits : Nonnegative-Fixnum (integer-length (rsa-public-n key)))
    (define k : Index (octets-length mbits))
    (define embits : Index (assert (- mbits 1) index?))
    (define em : Bytes (pkcs#1-v1.5-encode message embits (pkcs#1-hash-der id-hash) (pkcs#1-hash-method id-hash) rsa-sign peer-name))
    (define m : Natural (assert (pkcs#1-octets->integer em) exact-nonnegative-integer?))
    (define s : Natural (pkcs#1-rsa-sign key m))
    
    (pkcs#1-integer->octets s k)))

(define rsa-verify : (-> RSA-Key Bytes Bytes PKCS#1-Hash Symbol Boolean)
  ;; https://tools.ietf.org/html/rfc8017#section-8.2.2
  (lambda [key message signature id-hash peer-name]
    (define mbits : Nonnegative-Fixnum (integer-length (rsa-public-n key)))
    (define k : Index (octets-length mbits))

    (and (= k (bytes-length signature))
         (let* ([s (assert (pkcs#1-octets->integer signature) exact-nonnegative-integer?)]
                [m (pkcs#1-rsa-verify (rsa-public-n key) (rsa-public-e key) s)]
                [embits (assert (- mbits 1) index?)])
           (bytes=? (pkcs#1-v1.5-encode message embits (pkcs#1-hash-der id-hash) (pkcs#1-hash-method id-hash) rsa-verify peer-name)
                    (pkcs#1-integer->octets m k))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pkcs#1-v1.5-encode : (-> Bytes Index Bytes (-> Bytes Bytes) Procedure Symbol Bytes)
  (let ([0x0001 (bytes #x00 #x01)]
        [0x00 (bytes #x00)])
    (lambda [message embits der-head hash src peer-name]
      ; No need to check the max length of message, for SHA-1, it's (2^61 - 1), this limitation is impractical.
      (define emLen : Index (octets-length embits))
      (define T : Bytes (bytes-append der-head (hash message)))
      (define tLen : Index (bytes-length T))
      (define psLen : Integer (- emLen tLen 3))

      (cond [(byte? psLen) (bytes-append 0x0001 (make-bytes psLen #xFF) 0x00 T)]
            [else (throw exn:ssh:kex src peer-name
                         "intended encoded message length too short (~a < ~a)"
                         embits (+ tLen 3))]))))
