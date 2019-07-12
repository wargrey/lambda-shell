#lang typed/racket/base

;;; https://www.itu.int/rec/T-REC-X.680-201508-I/en
;;; https://www.itu.int/rec/T-REC-X.690-201508-I/en

(provide (all-defined-out))

(require digimon/number)

(require "../datatype.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type ASN.1-Tag-Class (U 'Universal 'Application 'Context-specific 'Private))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
          [else (let ([bsize : Bytes (natural->network-bytes size)])
                  (bytes-append (bytes (bitwise-ior (bytes-length bsize) #b10000000))
                                bsize))])))

(define asn-octets->length : (SSH-Bytes->Datum Natural)
  (lambda [blength [offset 0]]
    (define head-byte : Byte (bytes-ref blength offset))
    (cond [(< head-byte #b10000000) (values head-byte (+ offset 1))]
          [else (let* ([ssize (bitwise-and head-byte #b01111111)]
                       [idx0 (+ offset 1)]
                       [idxn (+ idx0 ssize)])
                  (values (network-bytes->natural blength idx0 idxn) idxn))])))
