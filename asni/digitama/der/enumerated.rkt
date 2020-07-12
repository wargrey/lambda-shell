#lang typed/racket/base

;;; https://www.itu.int/rec/T-REC-X.680-201508-I/en
;;; https://www.itu.int/rec/T-REC-X.690-201508-I/en

(provide (all-defined-out))

(require digimon/number)

(require "base.rkt")
(require "primitive.rkt")
(require "metatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/list))
(require (for-syntax racket/bool))

(require (for-syntax racket/syntax))
(require (for-syntax syntax/parse))

(require (for-syntax "metatype.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax (asn-enumerated-item <item>)
  (syntax-parse <item>
    [(id:id idx:integer) (values #'id #'idx)]
    [(id:id idx:char) (values #'id (datum->syntax #'idx (char->integer (syntax-e #'idx))))]
    [id:id (values #'id #false)]
    [_ (raise-syntax-error 'define-asn-enumerated "malformed enumeration item" <item>)]))

(define-for-syntax (asn-root-enumeration-parse <items> <fallback>)
  (define defined-secidni
    (for/fold ([secidni null])
              ([<item> (in-list (filter-not identifier? (syntax->list <items>)))])
      (define-values (<name> <defined-index>) (asn-enumerated-item <item>))
      (define idx (syntax-e <defined-index>))
      (cond [(nor (memq idx secidni) (member idx secidni)) (cons idx secidni)]
            [else (raise-syntax-error 'define-asn-enumerated "duplicated number" <defined-index>)])))

  (define fallback (or (syntax-e <fallback>) (if (null? defined-secidni) 0 (apply min defined-secidni))))
  (define-values (<id.idx>s fb-<id.idx>)
    (let auto-number ([<item>s (syntax->list <items>)]
                      [idx 0]
                      [sreifitnedi null]
                      [<smeti> null]
                      [fb-<id.idx> #false])
      (cond [(member idx defined-secidni) (auto-number <item>s (+ idx 1) sreifitnedi <smeti> fb-<id.idx>)]
            [(null? <item>s) (values (reverse <smeti>) fb-<id.idx>)]
            [else (let-values ([(<id> <idx>) (asn-enumerated-item (car <item>s))])
                    (define id (syntax-e <id>))
                    
                    (when (memq id sreifitnedi)
                      (raise-syntax-error 'define-asn-enumerated "duplicated identifier" <id>))

                    (define-values (index <index>)
                      (cond [(and <idx>) (values (syntax-e <idx>) <idx>)]
                            [else (values idx (datum->syntax <id> idx))]))

                    (auto-number (cdr <item>s) (+ idx 1) (cons id sreifitnedi) (cons (list <id> <index>) <smeti>)
                                 (or fb-<id.idx>
                                     (and (or (eq? fallback id) (equal? fallback index))
                                          (list <id> <index>)))))])))

  (when (null? <id.idx>s)
    (raise-syntax-error 'define-asn-enumerated "empty enumeration" <items>))
  
  (cond [(and fb-<id.idx>) (cons fb-<id.idx> <id.idx>s)]
        [else (raise-syntax-error 'define-asn-enumerated "unrecognized fallback value" <fallback>)]))

(define-syntax (define-asn-enumerated stx)
  (syntax-parse stx #:datum-literals [:]
    [(_ asn-enum : ASN-Enum
        (~alt (~optional (~seq #:+ Sub-Integer) #:defaults ([Sub-Integer #'Byte]))
              (~optional (~seq #:default fallback) #:defaults ([fallback #'#false]))) ...
        (item ...))
     (with-syntax* ([asn-enum->bytes (format-id #'asn-enum "~a->bytes" (syntax-e #'asn-enum))]
                    [unsafe-bytes->asn-enum (format-id #'asn-enum "unsafe-bytes->~a" (syntax-e #'asn-enum))]
                    [unsafe-bytes->asn-enum* (format-id #'asn-enum "unsafe-bytes->~a*" (syntax-e #'asn-enum))]
                    [([fb-id fb-idx] [identifier index] ...) (asn-root-enumeration-parse #'(item ...) #'fallback)]
                    [_ (asn-metatype-set! #'asn-enum #'ASN-Enum #'(ASN-Enum asn-enumerated-octets? asn-enum->bytes unsafe-bytes->asn-enum))])
       #'(begin (define-type ASN-Enum (U 'identifier ...))

                (define asn-enum : (case-> [-> (Pairof ASN-Enum (Listof ASN-Enum))] [Symbol -> Sub-Integer] [Integer -> ASN-Enum])
                  (let ([enum : (Pairof ASN-Enum (Listof ASN-Enum)) (list 'identifier ...)])
                    (case-lambda
                      [() enum]
                      [(v) (cond [(symbol? v) (case v [(identifier) index] ... [else fb-idx])]
                                 [else (case v [(index) 'identifier] ... [else 'fb-id])])])))

                (define asn-enum->bytes : (-> ASN-Enum Bytes)
                  (lambda [self]
                    (asn-octets-box asn-enumerated-id (integer->network-bytes (asn-enum self)))))
                
                (define unsafe-bytes->asn-enum : (->* (Bytes) (Natural) (Values ASN-Enum Natural))
                  (lambda [bseq [offset 0]]
                    (define-values (idx end) (unsafe-asn-bytes->integer bseq offset))
                    (values (asn-enum idx) end)))

                (define unsafe-bytes->asn-enum* : (->* (Bytes) (Natural) ASN-Enum)
                  (lambda [bseq [offset 0]]
                    (define-values (seq end) (unsafe-bytes->asn-enum bseq offset))
                    seq))

                (asn-der-metatype-set! 'asn-enum 'ASN-Enum '(ASN-Enum asn-enumerated-octets? asn-enum->bytes unsafe-bytes->asn-enum))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-enumerated : Byte (asn-identifier-octet 10 #:class 'Universal #:constructed? #false))
(define asn-enumerated-id : Bytes (bytes asn-enumerated))

(define asn-enumerated-octets? : (->* (Bytes) (Integer) Boolean)
  (lambda [basn [offset 0]]
    (and (> (bytes-length basn) offset)
         (= (bytes-ref basn offset) asn-enumerated))))
 