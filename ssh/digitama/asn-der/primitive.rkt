#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require "base.rkt")
(require "octets.rkt")
(require "../algorithm/pkcs/primitive.rkt")

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
                    [bytes->asn (format-id #'asn "asn-bytes->~a" (syntax-e #'type))]
                    [asn->bytes* (format-id #'asn "~a->bytes*" (syntax-e #'asn))]
                    [asn-datum (format-id #'asn "~a-datum" (syntax-e #'asn))])
       #'(begin (struct asn asn-type ([datum : Type]) #:transparent #:type-name ASN)

                (define asn-identifier : Byte (asn-identifier-octet tag #:class 'Universal #:constructed? #false))

                (define make-asn : (-> Type ASN)
                  (lambda [datum]
                    (asn asn-identifier datum)))

                (define asn->bytes : (-> ASN Bytes)
                  (lambda [self]
                    (asn->octets (asn-datum self))))

                (define bytes->asn : (-> Bytes Natural Natural ASN)
                  (lambda [basn start end]
                    (make-asn (octets->asn basn start end))))

                (define asn->bytes* : (-> ASN-Type (Option Bytes))
                  (lambda [self]
                    (and (asn? self)
                         (asn->bytes self))))

                (hash-set! asn-type->bytes-database asn-identifier asn->bytes*)
                (hash-set! asn-bytes->type-database asn-identifier bytes->asn)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-asn-primitive boolean : ASN-Boolean #:as Boolean #x01                                  [asn-boolean->octets asn-octets->boolean])
(define-asn-primitive integer : ASN-Integer #:as Integer #x02                                  [asn-integer->octets asn-octets->integer])
(define-asn-primitive bit-string : ASN-Bit-String #:as ASN-Bitset #x03                         [asn-bit-string->octets asn-octets->bit-string])
(define-asn-primitive octet-string : ASN-Octet-String #:as Bytes #x04                          [values subbytes])

(define-asn-primitive null : ASN-Null #:as Void #x05                                           [asn-null->octets void])
(define-asn-primitive oid : ASN-OID #:as ASN-Object-Identifier #x06                            [asn-oid->octets asn-octets->oid])
(define-asn-primitive relative-oid : ASN-Relative-OID #:as ASN-Relative-Object-Identifier #x0D [asn-relative-oid->octets asn-octets->relative-oid])

(define-asn-primitive string/utf8 : ASN-String/UTF8 #:as String #x0C                           [string->bytes/utf-8 asn-octets->string/utf8])
(define-asn-primitive string/printable : ASN-String/Printable #:as String #x13                 [string->bytes/latin-1 asn-octets->string/printable])
(define-asn-primitive string/ia5 : ASN-String/IA5 #:as String #x16                             [string->bytes/latin-1 asn-octets->string/ia5])
(define-asn-primitive string/bmp : ASN-String/BMP #:as String #x1E                             [asn-string->octets/bmp asn-octets->string/bmp])
