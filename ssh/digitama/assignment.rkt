#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250

(provide (all-defined-out))

(require "datatype.rkt")
(require "exception.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/string))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-for-syntax (ssh-typename <id>)
  (format-id <id> "~a" (string-replace (symbol->string (syntax-e <id>)) "_" "-")))

(define-for-syntax (ssh-typeid <id>)
  (format-id <id> "~a" (string-replace (string-downcase (symbol->string (syntax-e <id>))) "_" ":")))

(define-for-syntax (ssh-make-nbytes->bytes <n>)
  #`(λ [[braw : Bytes] [offset : Natural 0]] : (Values Bytes Natural)
      (define end (+ offset #,(syntax-e <n>)))
      (values (subbytes braw offset end)
              end)))

(define-for-syntax (ssh-datum-pipeline <FType>)
  (case (syntax->datum <FType>)
    [(Boolean) (list #'values #'ssh-boolean->bytes #'ssh-bytes->boolean #'values)]
    [(Index) (list #'values #'ssh-uint32->bytes #'ssh-bytes->uint32 #'values)]
    [(Natural) (list #'values #'ssh-uint64->bytes #'ssh-bytes->uint64 #'values)]
    [(String) (list #'values #'ssh-string->bytes #'ssh-bytes->string #'values)]
    [(Integer) (list #'values #'ssh-mpint->bytes #'ssh-bytes->mpint #'values)]
    [(Symbol) (list #'values #'ssh-name->bytes #'ssh-bytes->name #'values)]
    [(Bytes) (list #'values #'values #'ssh-values #'values)]
    [else (with-syntax* ([(TypeC argument) (syntax-e <FType>)]
                         [$type (format-id #'argument "$~a" (syntax-e #'argument))])
            (case (syntax-e #'TypeC)
              [(SSH-Bytes) (list #'values #'values (ssh-make-nbytes->bytes #'argument) #'values)]
              [(SSH-Symbol) (list #'$type #'ssh-uint32->bytes #'ssh-bytes->uint32 #'$type)]
              [(SSH-Namelist) (list #'values #'ssh-namelist->bytes #'ssh-bytes->namelist #'$type)]
              [else (list #'values #'ssh-namelist->bytes #'ssh-bytes->namelist #'values)]))]))

(define-syntax (define-ssh-symbols stx)
  (syntax-case stx [:]
    [(_ TypeU : Type ([enum val] ...))
     (with-syntax ([$id (format-id #'TypeU "$~a" (syntax-e #'TypeU))]
                   [(name ...) (for/list ([<enum> (in-syntax #'(enum ...))]) (ssh-typename <enum>))])
       #'(begin (define-type TypeU (U 'name ... 'enum ...))
                (define $id : (case-> [Symbol -> Type] [Integer -> TypeU])
                  (λ [v] (cond [(symbol? v) (case v [(enum name) val] ... [else 0])]
                               [else (case v [(val) 'name] ... [else (error 'TypeU "unrecognized assignment: ~a" v)])])))))]))

(define-syntax (define-ssh-names stx)
  (syntax-case stx [:]
    [(_ id : TypeU ([enum0 group0 comments0 ...] [enum group comments ...] ...))
     (with-syntax ([id? (format-id #'id "~a?" (syntax-e #'id))]
                   [id?* (format-id #'id "~a?*" (syntax-e #'id))]
                   [TypeU* (format-id #'TypeU "~a*" (syntax-e #'TypeU))])
     #'(begin (define-type TypeU (U 'enum0 'enum ...))
              (define-type TypeU* (Listof TypeU))
              (define id : (Pairof TypeU TypeU*) (cons 'enum0 (list 'enum ...)))
              (define id? : (-> Any Boolean : TypeU)
                (λ [v] (cond [(eq? v 'enum0) #true] [(eq? v 'enum) #true] ... [else #false])))
              (define id?* : (-> (Listof Any) Boolean : TypeU*)
                (λ [es] ((inst andmap Any Boolean TypeU) id? es)))))]))

(define-syntax (define-message stx)
  (syntax-case stx [:]
    [(_ id val ([field : FieldType defval ...] ...))
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [ssh:msg (ssh-typeid #'id)]
                    [constructor (format-id #'id "~a" (gensym 'ssh:msg:))]
                    [make-ssh:msg (format-id #'ssh:msg "make-~a" (syntax-e #'ssh:msg))]
                    [ssh:msg->bytes (format-id #'ssh:msg "~a->bytes" (syntax-e #'ssh:msg))]
                    [bytes->ssh:msg (format-id #'ssh:msg "bytes->~a" (syntax-e #'ssh:msg))]
                    [(c-args ...)
                     (for/fold ([syns null])
                               ([<field> (in-syntax #'(field ...))]
                                [<mkarg> (in-syntax #'([field : FieldType defval ...] ...))])
                       (cons (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>))))
                             (cons <mkarg> syns)))]
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket)] ...)
                     (for/list ([<field> (in-syntax #'(field ...))]
                                [<FType> (in-syntax #'(FieldType ...))])
                       (list (format-id <field> "~a-~a" (syntax-e #'ssh:msg) (syntax-e <field>))
                             (ssh-datum-pipeline <FType>)))])
       #'(begin (define-type SSH-MSG ssh:msg)
                (struct ssh:msg SSH-Message ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor)

                (define (make-ssh:msg c-args ...) : SSH-MSG
                  (constructor val 'id field ...))

                (define ssh:msg->bytes : (-> SSH-MSG Bytes)
                  (lambda [self]
                    (bytes-append (bytes (SSH-Message-id self))
                                  (ssh->bytes (racket->ssh (field-ref self)))
                                  ...)))

                (define bytes->ssh:msg : (->* (Bytes) (Index) (Option SSH-MSG))
                  (lambda [bmsg [offset 0]]
                    (and (= (bytes-ref bmsg offset) val)
                         (let*-values ([(offset) (+ offset 1)]
                                       [(field offset) (bytes->ssh bmsg offset)] ...)
                           (constructor val 'id (ssh->racket field) ...)))))

                (hash-set! ssh-bytes->message-database val bytes->ssh:msg)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Bytes->Message (->* (Bytes) (Index) (Option SSH-Message)))

(struct SSH-Message ([id : Byte] [name : Symbol]))

(define ssh-bytes->message-database : (HashTable Index SSH-Bytes->Message) (make-hasheq))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-values : (SSH-Bytes->Type Bytes)
  (lambda [braw [offset 0]]
    (define end : Index (bytes-length braw))
    (values (subbytes braw offset end)
            end)))