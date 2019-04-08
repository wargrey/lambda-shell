#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require "base.rkt")
(require "primitive.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(require (for-syntax "primitive.rkt"))

;;; TODO: why the database cannot shared by other modules?
(define-for-syntax asn-sequence-metainfo-database (make-hasheq))

(define-for-syntax (asn-sequence-field seqname <declaration>)
  (define declaration (syntax-e <declaration>))
  (define <field> (car declaration))
  (define <asn-type> (cadr declaration))
  (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))
  (define <field-ref> (format-id <field> "~a-~a" seqname (syntax-e <field>)))

  (define metainfo (hash-ref asn-type-metainfo-database (syntax-e <asn-type>)
                             (λ [] (hash-ref asn-sequence-metainfo-database (syntax-e <asn-type>)
                                             (λ [] (raise-syntax-error 'define-asn-sequence "not an ASN.1 type" <asn-type>))))))
  
  (define <Type> (datum->syntax <asn-type> (car metainfo)))
  (define <asn->bytes> (datum->syntax <asn-type> (cadr metainfo)))
  (define <bytes->asn> (datum->syntax <asn-type> (caddr metainfo)))
  (define-values (<argls> <value> <type>)
    (syntax-case (list* <field> <Type> (cddr declaration)) []
      [(field FieldType) (values #'[field : FieldType] #'field #'FieldType)]
      [(field FieldType #:optional) (values #'[field : (Option FieldType) #false] #'field #'(Option FieldType))]
      
      ; TODO: why it fails when `defval` is using other field names?
      [(field FieldType #:default defval) (values #'[field : (Option FieldType) #false] #'(or field defval) #'FieldType)]
      [_ (raise-syntax-error 'define-asn-sequence "malformed field declaration" <declaration>)]))
  (values <kw-name> <argls> (list <field-ref> <type> <value> <asn->bytes> <bytes->asn>)))

(define-syntax (define-asn-sequence stx)
  (syntax-case stx [:]
    [(_ asn-sequence : ASN-Sequence ([field : ASNType options ...] ...))
     (with-syntax* ([constructor (format-id #'asn-sequence "~a" (gensym 'asn:sequence:))]
                    [asn-sequence? (format-id #'asn-sequence "~a?" (syntax-e #'asn-sequence))]
                    [make-seq (format-id #'asn-sequence "make-~a" (syntax-e #'asn-sequence))]
                    [asn-seq->bytes (format-id #'asn-sequence "~a->bytes" (syntax-e #'asn-sequence))]
                    [bytes->asn-seq (format-id #'asn-sequence "bytes->~a" (syntax-e #'asn-sequence))]
                    [asn-seq->bytes* (format-id #'asn-sequence "~a->bytes*" (syntax-e #'asn-sequence))]
                    [([kw-args ...] [(field-ref Type init-values field->bytes bytes->field) ...])
                     (let-values ([(kw-args sofni)
                                   (for/fold ([syns null] [sofni null])
                                             ([<declaration> (in-syntax #'([field ASNType options ...] ...))])
                                     (define-values (<kw-name> <argls> metainfo) (asn-sequence-field (syntax-e #'asn-sequence) <declaration>))
                                     (values (cons <kw-name> (cons <argls> syns))
                                             (cons metainfo sofni)))])
                       (list kw-args (reverse sofni)))]
                    [_ (hash-set! asn-sequence-metainfo-database (syntax-e #'asn-sequence) (syntax->list #'(ASN-Sequence asn-seq->bytes unsafe-bytes->asn)))])
       #'(begin (struct asn-sequence ([field : Type] ...) #:transparent
                  #:constructor-name constructor
                  #:type-name ASN-Sequence)

                (define (make-seq kw-args ...) : ASN-Sequence
                  (constructor init-values ...))

                (define asn-seq->bytes : (-> ASN-Sequence Bytes)
                  (lambda [self]
                    (let ([octets (bytes-append (field->bytes (field-ref self)) ...)])
                      (bytes-append asn-sequence-octets
                                    (asn-length->octets (bytes-length octets))
                                    octets))))

                #;(define bytes->asn : (-> Bytes Natural Natural ASN)
                  (lambda [basn start end]
                    (make-asn (octets->asn basn start end))))

                #;(define asn->bytes* : (-> ASN-Type (Option Bytes))
                  (lambda [self]
                    (and (asn? self)
                         (asn->bytes self))))

                (hash-set! asn-type-metainfo-database 'asn-sequence '(ASN-Sequence asn-seq->bytes unsafe-bytes->asn))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-sequence : Byte (asn-identifier-octet #x10 #:class 'Universal #:constructed? #true))
(define asn-sequence-octets : Bytes (bytes asn-sequence))
