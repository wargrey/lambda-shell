#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690
;;; https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-der-encoding-of-asn-1-types

(provide (all-defined-out))

(require racket/unsafe/ops)

(require "../algorithm/pkcs/primitive.rkt")

(define-type (ASN-Octets->Datum t) (-> Bytes Natural Natural t))

(define asn-boolean->octets : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes #xFF) (bytes 0))))

(define asn-octets->boolean : (ASN-Octets->Datum Boolean)
  (lambda [bbool start end]
    (not (zero? (bytes-ref bbool start)))))

(define asn-integer->octets : (-> Integer Bytes)
  (let ([leading-zero : Bytes (bytes #b00000000)])
    (lambda [mpint]
      (define byte-length : Index (octets-length (add1 #|for sign bit|# (integer-length mpint))))
      (define os : Bytes (pkcs#1-integer->octets mpint byte-length))

      (cond [(or (<= mpint 0) (not (bitwise-bit-set? (unsafe-bytes-ref os 0) 7))) os]
            [else (bytes-append leading-zero os)]))))

(define asn-octets->integer : (ASN-Octets->Datum Integer)
  (lambda [bint start end0]
    (define end : Index (assert (if (<= end0 start) (bytes-length bint) end0) index?))
    (let OS2IP ([i : Natural start]
                [x : Integer (if (>= (bytes-ref bint start) #b10000000) -1 0)])
      (cond [(>= i end) x]
            [else (OS2IP (+ i 1)
                         (bitwise-ior (arithmetic-shift x 8)
                                      (bytes-ref bint i)))]))))
