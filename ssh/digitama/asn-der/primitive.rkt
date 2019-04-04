#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require racket/unsafe/ops)

(require "base.rkt")
(require "octets.rkt")
(require "../algorithm/pkcs/primitive.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-asn-primitive stx)
  (syntax-case stx [:]
    [(_ type : ASN #:as Type tag comments ...)
     (with-syntax* ([asn (format-id #'type "asn-~a" (syntax-e #'type))]
                    [asn? (format-id #'type "~a?" (syntax-e #'asn))]
                    [asn-identifier (format-id #'type "~a-identifier" (syntax-e #'asn))]
                    [make-asn (format-id #'asn "make-~a" (syntax-e #'asn))]
                    [asn->octets (format-id #'asn "~a->octets" (syntax-e #'asn))]
                    [octets->asn (format-id #'asn "asn-octets->~a" (syntax-e #'type))]
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
(define-asn-primitive boolean : ASN-Boolean #:as Boolean #x01)
(define-asn-primitive integer : ASN-Integer #:as Integer #x02)

(define-asn-primitive null : ASN-Null #:as Void #x05)
(define-asn-primitive oid : ASN-OID #:as ASN-Object-Identifier #x06 Object Identifier)
(define-asn-primitive relative-oid : ASN-Relative-OID #:as ASN-Relative-Object-Identifier #x0D Relative Object Identifier)
