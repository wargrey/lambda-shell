#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require racket/unsafe/ops)

(require "../datatype.rkt")
(require "../algorithm/pkcs/primitive.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type ASN.1-Tag-Class (U 'Universal 'Application 'Context-specific 'Private))

(struct asn-type ([id : Byte]) #:type-name ASN-Type)
(struct asn-eoc asn-type () #:type-name ASN-EOC)

(define asn-type->bytes : (-> ASN-Type Bytes)
  (lambda [self]
    (define id : Byte (asn-type-id self))
    (define maybe-asn->types : (Option (-> ASN-Type (Option Bytes))) (hash-ref asn-type->bytes-database id (λ [] #false)))
    (or (and maybe-asn->types
             (let ([maybe-octets (maybe-asn->types self)])
               (and (bytes? maybe-octets) maybe-octets)))
        (bytes #x00 #x00) #| End of Content, should not happen |#)))

(define asn-bytes->type : (->* (Bytes) (Index) (Values ASN-Type Natural))
  (lambda [basn [offset 0]]
    (define id : Byte (bytes-ref basn offset))
    (define maybe-types->asn : (Option (->* (Bytes) (Index) (Values ASN-Type Natural))) (hash-ref asn-bytes->type-database id (λ [] #false)))

    (cond [(and maybe-types->asn) (maybe-types->asn basn offset)]
          [else (values (asn-eoc 0) (assert offset index?))])))

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
          [else (let ([ssize : Index (octets-length (integer-length size))])
                  (define octets : Bytes (make-bytes (+ ssize 1)))
                  
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-type->bytes-database : (HashTable Byte (-> ASN-Type (Option Bytes))) (make-hasheq))
(define asn-bytes->type-database : (HashTable Byte (->* (Bytes) (Index) (Values ASN-Type Natural))) (make-hasheq))
