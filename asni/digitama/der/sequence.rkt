#lang typed/racket/base

;;; https://www.itu.int/rec/T-REC-X.680-201508-I/en
;;; https://www.itu.int/rec/T-REC-X.690-201508-I/en

(provide (all-defined-out))
(provide (all-from-out "primitive.rkt"))

(require "base.rkt")
(require "metatype.rkt")
(require "primitive.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(require (for-syntax "metatype.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax (asn-sequence-field seqname <declaration>)
  (define declaration (syntax-e <declaration>))
  (define <field> (car declaration))
  (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))
  (define <field-ref> (format-id <field> "~a-~a" seqname (syntax-e <field>)))

  (define-values (<Type> <asn-octets?> <asn->bytes> <bytes->asn>) (asn-metatype-ref 'define-asn-sequence (cadr declaration)))
  (define-values (<argls> <value> <type> <do-bytes->asn>)
    (syntax-case (list* <field> <Type> (cddr declaration)) []
      [(field FieldType) (values #'[field : FieldType] #'field #'FieldType <bytes->asn>)]
      [(field FieldType #:optional) (values #'[field : (Option FieldType) #false] #'field #'(Option FieldType)
                                            #`(make-asn-bytes->maybe-datum #,<asn-octets?> #,<bytes->asn> #false))]
      [(field FieldType #:default defval) (values #'[field : (Option FieldType) #false] #'(or field defval) #'FieldType
                                                  #`(make-asn-bytes->maybe-datum #,<asn-octets?> #,<bytes->asn> defval))]
      [_ (raise-syntax-error 'define-asn-sequence "malformed field declaration" <declaration>)]))

  (values <kw-name> <argls> (list <field-ref> <type> <value> <asn->bytes> <do-bytes->asn>)))

(define-syntax (define-asn-sequence stx)
  (syntax-case stx [:]
    [(_ asn-seq : ASN-Seq ([field : ASNType options ...] ...))
     (with-syntax* ([constructor (format-id #'asn-seq "~a" (gensym 'asn:sequence:))]
                    [make-seq (format-id #'asn-seq "make-~a" (syntax-e #'asn-seq))]
                    [asn-seq->bytes (format-id #'asn-seq "~a->bytes" (syntax-e #'asn-seq))]
                    [unsafe-bytes->asn-seq (format-id #'asn-seq "unsafe-bytes->~a" (syntax-e #'asn-seq))]
                    [unsafe-bytes->asn-seq* (format-id #'asn-seq "unsafe-bytes->~a*" (syntax-e #'asn-seq))]
                    [([kw-args ...] [(field-ref Type init-values field->bytes bytes->field) ...])
                     (let-values ([(kw-args sofni)
                                   (for/fold ([syns null] [sofni null])
                                             ([<declaration> (in-syntax #'([field ASNType options ...] ...))])
                                     (define-values (<kw-name> <argls> metainfo) (asn-sequence-field (syntax-e #'asn-seq) <declaration>))
                                     (values (cons <kw-name> (cons <argls> syns))
                                             (cons metainfo sofni)))])
                       (list kw-args (reverse sofni)))]
                    [_ (asn-metatype-set! #'asn-seq #'ASN-Seq #'(ASN-Seq asn-sequence-octets? asn-seq->bytes unsafe-bytes->asn-seq))])
       (syntax/loc stx
         (begin (struct asn-seq ([field : Type] ...) #:transparent
                  #:constructor-name constructor
                  #:type-name ASN-Seq)

                (define (make-seq kw-args ...) : ASN-Seq
                  (constructor init-values ...))

                (define asn-seq->bytes : (-> ASN-Seq Bytes)
                  (lambda [self]
                    (asn-octets-box asn-sequence-id (bytes-append (let ([v (field-ref self)]) (if v (field->bytes v) #"")) ...))))

                (define unsafe-bytes->asn-seq : (->* (Bytes) (Natural) (Values ASN-Seq Natural))
                  (lambda [bseq [offset 0]]
                    (define-values (size content-offset) (asn-octets->length bseq (+ offset 1)))
                   
                    (let*-values ([(field content-offset) (bytes->field bseq content-offset)] ...)
                      (values (constructor field ...)
                              content-offset))))

                (define unsafe-bytes->asn-seq* : (->* (Bytes) (Natural) ASN-Seq)
                  (lambda [bseq [offset 0]]
                    (define-values (seq end) (unsafe-bytes->asn-seq bseq offset))
                    seq))

                (asn-der-metatype-set! 'asn-seq 'ASN-Seq '(ASN-Seq asn-sequence-octets? asn-seq->bytes unsafe-bytes->asn-seq)))))]
    [(_ asn-seq-of : ASN-Seq-Of #:of ASNType)
     (with-syntax* ([asn-seq-of->bytes (format-id #'asn-seq-of "~a->bytes" (syntax-e #'asn-seq-of))]
                    [unsafe-bytes->asn-seq-of (format-id #'asn-seq-of "unsafe-bytes->~a" (syntax-e #'asn-seq-of))]
                    [unsafe-bytes->asn-seq-of* (format-id #'asn-seq-of "unsafe-bytes->~a*" (syntax-e #'asn-seq-of))]
                    [(Type asn-octets? asn->bytes bytes->asn) (call-with-values (λ [] (asn-metatype-ref 'define-asn-sequence #'ASNType)) list)]
                    [_ (asn-metatype-set! #'asn-seq-of #'ASN-Seq-Of #'(ASN-Seq-Of asn-sequence-octets? asn-seq-of->bytes unsafe-bytes->asn-seq-of))])
       (syntax/loc stx
         (begin (define-type ASN-Seq-Of (Listof Type))
                
                (define asn-seq-of->bytes : (-> ASN-Seq-Of Bytes)
                  (lambda [self]
                    (asn-octets-box asn-sequence-id (apply bytes-append (map asn->bytes self)))))

                (define unsafe-bytes->asn-seq-of : (->* (Bytes) (Natural) (Values ASN-Seq-Of Natural))
                  (lambda [bseq [offset 0]]
                    (define-values (offset++ end) (asn-octets-unbox bseq offset))
                    (let read-seq-of ([sqes : ASN-Seq-Of null]
                                      [idx : Natural offset++])
                      (cond [(or (>= idx end) (not (asn-octets? bseq idx))) (values (reverse sqes) idx)]
                            [else (let-values ([(asn end) (bytes->asn bseq idx)])
                                    (read-seq-of (cons asn sqes) end))]))))

                (define unsafe-bytes->asn-seq-of* : (->* (Bytes) (Natural) ASN-Seq-Of)
                  (lambda [bseq [offset 0]]
                    (define-values (seq end) (unsafe-bytes->asn-seq-of bseq offset))
                    seq))

                (asn-der-metatype-set! 'asn-seq-of 'ASN-Seq-Of '(ASN-Seq-Of asn-sequence-octets? asn-seq-of->bytes unsafe-bytes->asn-seq-of)))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-sequence : Byte (asn-identifier-octet #x10 #:class 'Universal #:constructed? #true))
(define asn-sequence-id : Bytes (bytes asn-sequence))

(define asn-sequence-octets? : (->* (Bytes) (Integer) Boolean)
  (lambda [basn [offset 0]]
    (and (> (bytes-length basn) offset)
         (= (bytes-ref basn offset) asn-sequence))))
