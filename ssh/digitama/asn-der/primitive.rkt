#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))
(provide (for-syntax (all-defined-out)))

(require "base.rkt")
(require "octets.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-asn-primitive stx)
  (syntax-case stx [:]
    [(_ type : ASN #:as Type tag [asn->octets octets->asn] comments ...)
     (with-syntax* ([asn (format-id #'type "asn-~a" (syntax-e #'type))]
                    [asn? (format-id #'type "~a?" (syntax-e #'asn))]
                    [asn-identifier (format-id #'type "~a-identifier" (syntax-e #'asn))]
                    [make-asn (format-id #'asn "make-~a" (syntax-e #'asn))]
                    [asn->bytes (format-id #'asn "~a->bytes" (syntax-e #'asn))]
                    [unsafe-bytes->asn (format-id #'asn "unsafe-asn-bytes->~a" (syntax-e #'type))]
                    [unsafe-bytes->asn* (format-id #'asn "unsafe-asn-bytes->~a*" (syntax-e #'type))]
                    [ASN->type (format-id #'asn "~a" (gensym 'asn:))]
                    [asn-datum (format-id #'asn "~a-datum" (syntax-e #'asn))])
       #'(begin (define-type ASN asn) ; keep `asn` a role of type name for asn.1 constructed types
                (struct asn asn-type ([datum : Type]) #:transparent)

                (define asn-identifier : Byte (asn-identifier-octet tag #:class 'Universal #:constructed? #false))

                (define make-asn : (-> Type ASN)
                  (lambda [datum]
                    (asn asn-identifier datum)))

                (define asn->bytes : (-> ASN Bytes)
                  (let ([id (bytes asn-identifier)])
                    (lambda [self]
                      (let ([octets (asn->octets (asn-datum self))])
                        (bytes-append id (asn-length->octets (bytes-length octets)) octets)))))

                (define unsafe-bytes->asn : (->* (Bytes) (Index) (Values ASN Natural))
                  (lambda [basn [offset 0]]
                    (define-values (size content-offset) (asn-octets->length basn (+ offset 1)))
                    (define end : Natural (+ size content-offset))
                    
                    (values (make-asn (octets->asn basn content-offset end))
                            end)))
                
                (define unsafe-bytes->asn* : (->* (Bytes) (Index) ASN)
                  (lambda [basn [offset 0]]
                    (define-values (datum end-index) (unsafe-bytes->asn basn offset))
                    datum))

                (define ASN->type : (-> ASN-Type (Option Bytes))
                  (lambda [self]
                    (and (asn? self)
                         (asn->bytes self))))

                (hash-set! asn-type->bytes-database asn-identifier ASN->type)
                (hash-set! asn-bytes->type-database asn-identifier unsafe-bytes->asn)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-asn-primitive boolean : ASN-Boolean #:as Boolean #x01                                  [asn-boolean->octets asn-octets->boolean])
(define-asn-primitive integer : ASN-Integer #:as Integer #x02                                  [asn-integer->octets pkcs#1-octets->integer])
(define-asn-primitive bit-string : ASN-Bit-String #:as ASN-Bitset #x03                         [asn-bit-string->octets asn-octets->bit-string])
(define-asn-primitive octet-string : ASN-Octet-String #:as Bytes #x04                          [values subbytes])

(define-asn-primitive null : ASN-Null #:as Void #x05                                           [asn-null->octets void])
(define-asn-primitive oid : ASN-OID #:as ASN-Object-Identifier #x06                            [asn-oid->octets asn-octets->oid])
(define-asn-primitive relative-oid : ASN-Relative-OID #:as ASN-Relative-Object-Identifier #x0D [asn-relative-oid->octets asn-octets->relative-oid])

(define-asn-primitive string/utf8 : ASN-String/UTF8 #:as String #x0C                           [string->bytes/utf-8 asn-octets->string/utf8])
(define-asn-primitive string/printable : ASN-String/Printable #:as String #x13                 [string->bytes/latin-1 asn-octets->string/printable])
(define-asn-primitive string/ia5 : ASN-String/IA5 #:as String #x16                             [string->bytes/latin-1 asn-octets->string/ia5])
(define-asn-primitive string/bmp : ASN-String/BMP #:as String #x1E                             [asn-string->octets/bmp asn-octets->string/bmp])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn:null : ASN-Null (make-asn-null (void)))
