#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require racket/unsafe/ops)

(require "../datatype.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type ASN.1-Tag-Class (U 'Universal 'Application 'Context-specific 'Private))

;; TODO: long form identifier
(define asn-identifier-octet : (-> Byte [#:class ASN.1-Tag-Class] [#:constructed? Boolean] Byte)
  (lambda [tag #:class [class 'Universal] #:constructed? [constructed? #false]]
    (bitwise-ior (case class
                   [(Application)      #b01000000]
                   [(Context-specific) #b10000000]
                   [(Private)          #b11000000]
                   [else               #b00000000])
                 (if constructed?      #b00100000 #b00000000)
                 tag)))

(define asn-identifier-info : (-> Byte (Values Byte ASN.1-Tag-Class Boolean))
  (lambda [octet]
    (values (asn-identifier-tag octet)
            (asn-identifier-class octet)
            (asn-identifier-constructed? octet))))

(define asn-identifier-tag : (-> Byte Byte)
  (lambda [octet]
    (bitwise-and octet #b00011111)))

(define asn-identifier-class : (-> Byte ASN.1-Tag-Class)
  (lambda [octet]
    (case (arithmetic-shift octet -6)
      [(#b01) 'Application]
      [(#b10) 'Context-specific]
      [(#b11) 'Private]
      [else   'Universal])))

(define asn-identifier-constructed? : (-> Byte Boolean)
  (lambda [octet]
    (bitwise-bit-set? octet 5)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-length->octets : (-> Index Bytes)
  (lambda [size]
    (cond [(<= size 127) (bytes size)]
          [else (let-values ([(q r) (quotient/remainder size 256)])
                  (define osize : Positive-Fixnum (+ q (if (= r 0) 1 2)))
                  (define ssize : Nonnegative-Fixnum (- osize 1))
                  (define octets : Bytes (make-bytes osize))
                  
                  (case ssize
                    [(1 2 4 8) (integer->integer-bytes size ssize #false #true octets 1)]
                    [else (let length->bytes ([idx : Fixnum ssize]
                                              [size : Nonnegative-Fixnum size])
                            (when (>= idx 1)
                              (unsafe-bytes-set! octets idx (unsafe-fxand size #xFF))
                              (length->bytes (- idx 1) (unsafe-fxrshift size 8))))])

                  (unsafe-bytes-set! octets 0 (bitwise-ior ssize #b10000000))
                  octets)])))

(define asn-octets->length : (SSH-Bytes->Datum Index)
  (lambda [blength [offset 0]]
    (define head-byte : Byte (bytes-ref blength offset))
    (cond [(not (bitwise-bit-set? head-byte 7)) (values head-byte (unsafe-fx+ offset 1))]
          [else (let* ([ssize (bitwise-and head-byte #b01111111)]
                       [idx0 (unsafe-fx+ offset 1)]
                       [idxn (unsafe-fx+ idx0 ssize)])
                  (values (assert (case ssize
                                    [(1 2 4 8) (integer-bytes->integer blength #false #true (+ offset 1) idxn)]
                                    [else (let bytes->length : Natural ([size : Natural 0]
                                                                        [idx : Positive-Fixnum idx0])
                                            (cond [(>= idx idxn) size]
                                                  [else (bytes->length (unsafe-fxior (unsafe-fxlshift size 8) (bytes-ref blength idx))
                                                                       (unsafe-fx+ idx 1))]))]) index?)
                          idxn))])))

(define asn-boolean->octets : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes #xFF) (bytes 0))))

(define asn-octets->boolean : (SSH-Bytes->Datum Boolean)
  (lambda [bbool [offset 0]]
    (values (not (zero? (bytes-ref bbool offset)))
            (unsafe-fx+ offset 1))))
