#lang typed/racket/base

(provide (all-defined-out))
(provide (for-syntax (all-defined-out)))

(require "base.rkt")
(require "primitive.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(require (for-syntax "primitive.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax asn-metatype-database (make-hasheq))

(define-for-syntax (asn-metatype-ref func <asn-type>)
  (define metatype (hash-ref asn-type-metainfo-database (syntax-e <asn-type>)
                             (λ [] (hash-ref asn-metatype-database (syntax-e <asn-type>)
                                             (λ [] (raise-syntax-error func "not an ASN.1 type" <asn-type>))))))
  
  (define <Type> (datum->syntax <asn-type> (car metatype)))
  (define <asn-octets?> (datum->syntax <asn-type> (cadr metatype)))
  (define <asn->bytes> (datum->syntax <asn-type> (caddr metatype)))
  (define <bytes->asn> (datum->syntax <asn-type> (cadddr metatype)))
  
  (values <Type> <asn-octets?> <asn->bytes> <bytes->asn>))

(define-for-syntax (asn-metatype-set! <asn-type> <ASN-Type> <info>)
  (define info (syntax->list <info>))
  (define asn-type (syntax-e <asn-type>))
  (define ASN-Type (syntax-e <ASN-Type>))
  
  (hash-set! asn-metatype-database asn-type info)

  (unless (eq? asn-type ASN-Type)
    (hash-set! asn-metatype-database ASN-Type info)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-der-metatype-set! : (-> Symbol Symbol (Listof Symbol) Void)
  (lambda [asn-type ASN-Type info]
    (hash-set! asn-type-metainfo-database asn-type info)

    (unless (eq? asn-type ASN-Type)
      (hash-set! asn-type-metainfo-database ASN-Type info))))

(define make-asn-bytes->maybe-datum : (All (T V) (-> (->* (Bytes) (Integer) Boolean) (->* (Bytes) (Natural) (Values T Natural)) V
                                                     (->* (Bytes) (Natural) (Values (U T V) Natural))))
  (lambda [asn-octets? bytes->asn defval]
    (λ [[basn : Bytes] [offset : Natural 0]] : (Values (U T V) Natural)
      (cond [(asn-octets? basn offset) (bytes->asn basn offset)]
            [else (values defval offset)]))))
