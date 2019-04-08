#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))

(require "base.rkt")
(require "primitive.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax syntax/parse))

#;(define-syntax (define-message-interface stx)
  (syntax-case stx [:]
    [(_ id val ([field : FieldType defval ...] ...))
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [ssh:msg (ssh-typeid #'id)]
                    [constructor (format-id #'id "~a" (gensym 'ssh:msg:))]
                    [SSH:MSG->bytes (format-id #'ssh:msg "~a" (gensym 'ssh:msg:))]
                    [ssh:msg? (format-id #'ssh:msg "~a?" (syntax-e #'ssh:msg))]
                    [make-ssh:msg (format-id #'ssh:msg "make-~a" (syntax-e #'ssh:msg))]
                    [ssh:msg->bytes (format-id #'ssh:msg "~a->bytes" (syntax-e #'ssh:msg))]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))]
                    [unsafe-bytes->ssh:msg* (format-id #'ssh:msg "unsafe-bytes->~a*" (syntax-e #'ssh:msg))]
                    [([kw-args ...] [init-values ...])
                     (let-values ([(kw-args seulav)
                                   (for/fold ([syns null] [slav null])
                                             ([<declaration> (in-syntax #'([field FieldType defval ...] ...))])
                                     (define-values (<kw-name> <argls> <value>) (ssh-struct-field <declaration>))
                                     (values (cons <kw-name> (cons <argls> syns))
                                             (cons <value> slav)))])
                       (list kw-args (reverse seulav)))]
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket)] ...)
                     (for/list ([<field> (in-syntax #'(field ...))]
                                [<FType> (in-syntax #'(FieldType ...))])
                       (list (format-id <field> "~a-~a" (syntax-e #'ssh:msg) (syntax-e <field>))
                             (ssh-datum-pipeline 'define-ssh-messages <FType>)))])
       #'(begin (struct ssh:msg ssh-message ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor #:type-name SSH-MSG)

                (define (make-ssh:msg kw-args ...) : SSH-MSG
                  (constructor val 'SSH-MSG init-values ...))

                (define ssh:msg->bytes : (-> SSH-MSG Bytes)
                  (let ([head-byte : Bytes (bytes val)])
                    (lambda [self]
                      (bytes-append head-byte
                                    (ssh->bytes (racket->ssh (field-ref self)))
                                    ...))))

                (define unsafe-bytes->ssh:msg : (->* (Bytes) (Index) (Values SSH-MSG Nonnegative-Fixnum))
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(offset) (+ offset 1)]
                                  [(field offset) (bytes->ssh bmsg offset)] ...)
                      (values (constructor val 'SSH-MSG (ssh->racket field) ...)
                              offset))))

                (define unsafe-bytes->ssh:msg* : (->* (Bytes) (Index) SSH-MSG)
                  (lambda [bmsg [offset 0]]
                    (define-values (message end-index) (unsafe-bytes->ssh:msg bmsg offset))
                    message))

                (define SSH:MSG->bytes : (-> SSH-Message (Option Bytes))
                  (lambda [self]
                    (and (ssh:msg? self)
                         (ssh:msg->bytes self))))
                
                (hash-set! ssh-message->bytes-database 'SSH-MSG SSH:MSG->bytes)))]))

(define-syntax (define-asn-sequence stx)
  (syntax-case stx [:]
    [(_ type : ASN ([field : FieldType defval ...] ...))
     (with-syntax* ([asn (format-id #'type "asn-~a" (syntax-e #'type))]
                    [asn? (format-id #'type "~a?" (syntax-e #'asn))]
                    [asn-identifier (format-id #'type "~a-identifier" (syntax-e #'asn))]
                    [make-asn (format-id #'asn "make-~a" (syntax-e #'asn))]
                    [asn->bytes (format-id #'asn "~a->bytes" (syntax-e #'asn))]
                    [bytes->asn (format-id #'asn "asn-bytes->~a" (syntax-e #'type))]
                    [asn->bytes* (format-id #'asn "~a->bytes*" (syntax-e #'asn))]
                    [asn-datum (format-id #'asn "~a-datum" (syntax-e #'asn))])
       #'(begin (struct asn asn-type ([datum : Datum]) #:transparent #:type-name ASN)

                (define asn-identifier : Byte (asn-identifier-octet #x10 #:class 'Universal #:constructed? #true))

                (define make-asn : (-> Datum ASN)
                  (lambda [datum]
                    (asn asn-identifier datum)))

                #;(define asn->bytes : (-> ASN Bytes)
                  (lambda [self]
                    (bytes-append (asn-datum self))))

                #;(define bytes->asn : (-> Bytes Natural Natural ASN)
                  (lambda [basn start end]
                    (make-asn (octets->asn basn start end))))

                #;(define asn->bytes* : (-> ASN-Type (Option Bytes))
                  (lambda [self]
                    (and (asn? self)
                         (asn->bytes self))))

                #;(hash-set! asn-type->bytes-database asn-identifier asn->bytes*)
                #;(hash-set! asn-bytes->type-database asn-identifier bytes->asn)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-asn-sequence seq : ASN-Seq
  ([name : ASN-String/IA5]
   [ok : ASN-Boolean]))
