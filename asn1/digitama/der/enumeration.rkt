#lang typed/racket/base

;;; https://www.itu.int/rec/T-REC-X.680-201508-I/en
;;; https://www.itu.int/rec/T-REC-X.690-201508-I/en

(provide (all-defined-out))
(provide (all-from-out "primitive.rkt"))

(require "base.rkt")
(require "primitive.rkt")
(require "../octets.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(require (for-syntax "primitive.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax asn-enumeration-metainfo-database (make-hasheq))

(define-for-syntax (asn-type-info <asn-type>)
  (define metainfo (hash-ref asn-type-metainfo-database (syntax-e <asn-type>)
                             (λ [] (hash-ref asn-enumeration-metainfo-database (syntax-e <asn-type>)
                                             (λ [] (raise-syntax-error 'define-asn-sequence "not an ASN.1 type" <asn-type>))))))
  
  (define <Type> (datum->syntax <asn-type> (car metainfo)))
  (define <asn-octets?> (datum->syntax <asn-type> (cadr metainfo)))
  (define <asn->bytes> (datum->syntax <asn-type> (caddr metainfo)))
  (define <bytes->asn> (datum->syntax <asn-type> (cadddr metainfo)))
  
  (values <Type> <asn-octets?> <asn->bytes> <bytes->asn>))

(define-for-syntax (asn-enumeration-field seqname <declaration>)
  (define declaration (syntax-e <declaration>))
  (define <field> (car declaration))
  (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))
  (define <field-ref> (format-id <field> "~a-~a" seqname (syntax-e <field>)))

  (define-values (<Type> <asn-octets?> <asn->bytes> <bytes->asn>) (asn-type-info (cadr declaration)))
  (define-values (<argls> <value> <type> <do-bytes->asn>)
    (syntax-case (list* <field> <Type> (cddr declaration)) []
      [(field FieldType) (values #'[field : FieldType] #'field #'FieldType <bytes->asn>)]
      [(field FieldType #:optional) (values #'[field : (Option FieldType) #false] #'field #'(Option FieldType)
                                            #`(make-asn-bytes->maybe-datum #,<asn-octets?> #,<bytes->asn> #false))]
      [(field FieldType #:default defval) (values #'[field : (Option FieldType) #false] #'(or field defval) #'FieldType
                                                  #`(make-asn-bytes->maybe-datum #,<asn-octets?> #,<bytes->asn> defval))]
      [_ (raise-syntax-error 'define-asn-enumeration "malformed field declaration" <declaration>)]))

  (values <kw-name> <argls> (list <field-ref> <type> <value> <asn->bytes> <do-bytes->asn>)))

(define-syntax (define-asn-enumeration stx)
  (syntax-case stx [:]
    [(_ asn-sequence : ASN-Sequence ([field : ASNType options ...] ...))
     (with-syntax* ([constructor (format-id #'asn-sequence "~a" (gensym 'asn:sequence:))]
                    [make-seq (format-id #'asn-sequence "make-~a" (syntax-e #'asn-sequence))]
                    [asn-seq->bytes (format-id #'asn-sequence "~a->bytes" (syntax-e #'asn-sequence))]
                    [unsafe-bytes->asn-seq (format-id #'asn-sequence "unsafe-bytes->~a" (syntax-e #'asn-sequence))]
                    [unsafe-bytes->asn-seq* (format-id #'asn-sequence "unsafe-bytes->~a*" (syntax-e #'asn-sequence))]
                    [([kw-args ...] [(field-ref Type init-values field->bytes bytes->field) ...])
                     (let-values ([(kw-args sofni)
                                   (for/fold ([syns null] [sofni null])
                                             ([<declaration> (in-syntax #'([field ASNType options ...] ...))])
                                     (define-values (<kw-name> <argls> metainfo) (asn-enumeration-field (syntax-e #'asn-sequence) <declaration>))
                                     (values (cons <kw-name> (cons <argls> syns))
                                             (cons metainfo sofni)))])
                       (list kw-args (reverse sofni)))]
                    [(_ _) (let ([info (syntax->list #'(ASN-Sequence asn-enumeration-octets? asn-seq->bytes unsafe-bytes->asn-seq))])
                             (list (hash-set! asn-enumeration-metainfo-database (syntax-e #'asn-sequence) info)
                                   (hash-set! asn-enumeration-metainfo-database (syntax-e #'ASN-Sequence) info)))])
       #'(begin (struct asn-sequence ([field : Type] ...) #:transparent
                  #:constructor-name constructor
                  #:type-name ASN-Sequence)

                (define (make-seq kw-args ...) : ASN-Sequence
                  (constructor init-values ...))

                (define asn-seq->bytes : (-> ASN-Sequence Bytes)
                  (lambda [self]
                    (asn-enumeration-box (bytes-append (let ([v (field-ref self)]) (if v (field->bytes v) #"")) ...))))

                (define unsafe-bytes->asn-seq : (->* (Bytes) (Natural) (Values ASN-Sequence Natural))
                  (lambda [bseq [offset 0]]
                    (define-values (size content-offset) (asn-octets->length bseq (+ offset 1)))
                   
                    (let*-values ([(field content-offset) (bytes->field bseq content-offset)] ...)
                      (values (constructor field ...)
                              content-offset))))

                (define unsafe-bytes->asn-seq* : (->* (Bytes) (Natural) ASN-Sequence)
                  (lambda [bseq [offset 0]]
                    (define-values (seq end) (unsafe-bytes->asn-seq bseq offset))
                    seq))

                (hash-set! asn-type-metainfo-database 'asn-sequence '(ASN-Sequence asn-enumeration-octets? asn-seq->bytes unsafe-bytes->asn-seq))
                (hash-set! asn-type-metainfo-database 'ASN-Sequence '(ASN-Sequence asn-enumeration-octets? asn-seq->bytes unsafe-bytes->asn-seq))))]
    [(_ asn-seq-of : ASN-Seq-Of #:of ASNType)
     (with-syntax* ([asn-seq-of->bytes (format-id #'asn-seq-of "~a->bytes" (syntax-e #'asn-seq-of))]
                    [unsafe-bytes->asn-seq-of (format-id #'asn-seq-of "unsafe-bytes->~a" (syntax-e #'asn-seq-of))]
                    [unsafe-bytes->asn-seq-of* (format-id #'asn-seq-of "unsafe-bytes->~a*" (syntax-e #'asn-seq-of))]
                    [(Type asn-octets? asn->bytes bytes->asn) (call-with-values (λ [] (asn-type-info #'ASNType)) list)]
                    [(_ _) (let ([info (syntax->list #'(ASN-Seq-Of asn-enumeration-octets? asn-seq-of->bytes unsafe-bytes->asn-seq-of))])
                             (list (hash-set! asn-enumeration-metainfo-database (syntax-e #'asn-seq-of) info)
                                   (hash-set! asn-enumeration-metainfo-database (syntax-e #'ASN-Seq-Of) info)))])
       #'(begin (define-type ASN-Seq-Of (Listof Type))
                
                (define asn-seq-of->bytes : (-> ASN-Seq-Of Bytes)
                  (lambda [self]
                    (asn-enumeration-box (apply bytes-append (map asn->bytes self)))))

                (define unsafe-bytes->asn-seq-of : (->* (Bytes) (Natural) (Values ASN-Seq-Of Natural))
                  (lambda [bseq [offset 0]]
                    (define-values (offset++ end) (asn-enumeration-unbox bseq offset))
                    (let read-seq-of ([sqes : ASN-Seq-Of null]
                                      [idx : Natural offset++])
                      (cond [(or (>= idx end) (not (asn-octets? bseq idx))) (values (reverse sqes) idx)]
                            [else (let-values ([(asn end) (bytes->asn bseq idx)])
                                    (read-seq-of (cons asn sqes) end))]))))

                (define unsafe-bytes->asn-seq-of* : (->* (Bytes) (Natural) ASN-Seq-Of)
                  (lambda [bseq [offset 0]]
                    (define-values (seq end) (unsafe-bytes->asn-seq-of bseq offset))
                    seq))

                (hash-set! asn-type-metainfo-database 'asn-seq-of '(ASN-Seq-Of asn-enumeration-octets? asn-seq-of->bytes unsafe-bytes->asn-seq-of))
                (hash-set! asn-type-metainfo-database 'ASN-Seq-Of '(ASN-Seq-Of asn-enumeration-octets? asn-seq-of->bytes unsafe-bytes->asn-seq-of))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-enumeration : Byte (asn-identifier-octet 10 #:class 'Universal #:constructed? #false))

(define asn-enumeration-octets? : (->* (Bytes) (Integer) Boolean)
  (lambda [basn [offset 0]]
    (and (> (bytes-length basn) offset)
         (= (bytes-ref basn offset) asn-enumeration))))

(define asn-enumeration-box : (-> Bytes Bytes)
  (let ([id (bytes asn-enumeration)])
    (lambda [octets]
      (bytes-append id (asn-length->octets (bytes-length octets)) octets))))

(define asn-enumeration-unbox : (->* (Bytes) (Natural) (Values Natural Index))
  (lambda [octets [offset 0]]
    (define-values (size offset++) (asn-octets->length octets (+ offset 1)))
    (values offset++ (assert (+ offset++ size) index?))))
 