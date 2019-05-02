#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide (for-syntax ssh-typename ssh-typeid))
(provide unsafe-struct*-ref)

(require racket/unsafe/ops)

(require "datatype.rkt")

(require "../datatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/string))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))
(require (for-syntax syntax/parse))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax (ssh-typename <id>)
  (format-id <id> "~a" (string-replace (symbol->string (syntax-e <id>)) "_" "-")))

(define-for-syntax (ssh-typeid <id>)
  (format-id <id> "~a" (string-replace (string-downcase (symbol->string (syntax-e <id>))) "_" ":")))

(define-for-syntax (ssh-field-index <key> <fields>)
  (define key (syntax->datum <key>))

  (let search-key ([fields (syntax->datum <fields>)]
                   [index 0])
    (cond [(null? fields) (raise-syntax-error 'ssh-field-index "no such field" <key> #false (syntax-e <fields>))]
          [(eq? key (car fields)) (datum->syntax <key> index)]
          [else (search-key (cdr fields) (+ index 1))])))

(define-for-syntax (ssh-make-nbytes->bytes <n>)
  #`(λ [[braw : Bytes] [offset : Natural 0]] : (Values Bytes Natural)
      (let ([end (+ offset #,(syntax-e <n>))])
        (values (subbytes braw offset end) end))))

(define-for-syntax (ssh-datum-pipeline func <FType>)
  (case (syntax->datum <FType>)
    [(Boolean)     (list #'values #'ssh-boolean->bytes #'ssh-bytes->boolean #'values #'ssh-boolean-length)]
    [(Index)       (list #'values #'ssh-uint32->bytes  #'ssh-bytes->uint32  #'values #'ssh-uint32-length)]
    [(Natural)     (list #'values #'ssh-uint64->bytes  #'ssh-bytes->uint64  #'values #'ssh-uint64-length)]
    [(String)      (list #'values #'ssh-string->bytes  #'ssh-bytes->string  #'values #'ssh-string-length)]
    [(SSH-BString) (list #'values #'ssh-bstring->bytes #'ssh-bytes->bstring #'values #'ssh-bstring-length)]
    [(Integer)     (list #'values #'ssh-mpint->bytes   #'ssh-bytes->mpint   #'values #'ssh-mpint-length)]
    [(Symbol)      (list #'values #'ssh-name->bytes    #'ssh-bytes->name    #'values #'ssh-name-length)]
    [(Bytes)       (list #'values #'ssh-bytes->bytes   #'ssh-values         #'values #'bytes-length)]
    [else (with-syntax* ([(TypeOf T) (syntax-e <FType>)]
                         [$type (format-id #'T "$~a" (syntax-e #'T))])
            (case (syntax-e #'TypeOf)
              [(SSH-Bytes)            (list #'values                #'ssh-bytes->bytes    (ssh-make-nbytes->bytes #'T) #'values #'bytes-length)]
              [(SSH-Symbol)           (list #'$type                 #'ssh-uint32->bytes   #'ssh-bytes->uint32          #'$type  #'ssh-uint32-length)]
              [(SSH-Algorithm-Listof) (list #'ssh-algorithms->names #'ssh-namelist->bytes #'ssh-bytes->namelist        #'$type  #'ssh-namelist-length)]
              [else (if (and (free-identifier=? #'TypeOf #'Listof) (free-identifier=? #'T #'Symbol))
                        (list #'values #'ssh-namelist->bytes #'ssh-bytes->namelist #'values #'ssh-namelist-length)
                        (raise-syntax-error func "invalid SSH data type" <FType>))]))]))

(define-syntax (define-message-interface stx)
  (syntax-case stx [:]
    [(_ id val ([field : FieldType defval ...] ...))
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [ssh:msg (ssh-typeid #'id)]
                    [constructor (format-id #'id "~a" (gensym 'ssh:msg:))]
                    [ssh:msg? (format-id #'ssh:msg "~a?" (syntax-e #'ssh:msg))]
                    [ssh:msg-length (format-id #'ssh:msg "~a-length" (syntax-e #'ssh:msg))]
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
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket ssh-datum-length)] ...)
                     (for/list ([<field> (in-syntax #'(field ...))]
                                [<FType> (in-syntax #'(FieldType ...))])
                       (list (format-id <field> "~a-~a" (syntax-e #'ssh:msg) (syntax-e <field>))
                             (ssh-datum-pipeline 'define-ssh-messages <FType>)))])
       #'(begin (struct ssh:msg ssh-message ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor #:type-name SSH-MSG)

                (define (make-ssh:msg kw-args ...) : SSH-MSG
                  (constructor val 'SSH-MSG init-values ...))

                (define ssh:msg-length : (-> SSH-MSG Positive-Integer)
                  (lambda [self]
                    (+ 1 ; message number
                       (ssh-datum-length (racket->ssh (field-ref self)))
                       ...)))

                (define ssh:msg->bytes : (SSH-Datum->Bytes SSH-MSG)
                  (case-lambda
                    [(self) (bytes-append (bytes val) (ssh->bytes (racket->ssh (field-ref self))) ...)]
                    [(self pool) (ssh:msg->bytes self pool 0)]
                    [(self pool offset) (let* ([offset++ (+ offset 1)]
                                               [offset++ (ssh->bytes (racket->ssh (field-ref self)) pool offset++)] ...)
                                          (bytes-set! pool offset val)
                                          offset++)]))

                (define unsafe-bytes->ssh:msg : (->* (Bytes) (Index) (Values SSH-MSG Natural))
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(offset) (+ offset 1)]
                                  [(field offset) (bytes->ssh bmsg offset)] ...)
                      (values (constructor val 'SSH-MSG (ssh->racket field) ...)
                              offset))))

                (define unsafe-bytes->ssh:msg* : (->* (Bytes) (Index) SSH-MSG)
                  (lambda [bmsg [offset 0]]
                    (define-values (message end-index) (unsafe-bytes->ssh:msg bmsg offset))
                    message))

                (hash-set! ssh-message-length-database 'SSH-MSG
                           (λ [[self : SSH-Message]] (ssh:msg-length (assert self ssh:msg?))))
                
                (hash-set! ssh-message->bytes-database 'SSH-MSG
                           (case-lambda
                             [([self : SSH-Message])
                              (ssh:msg->bytes (assert self ssh:msg?))]
                             [([self : SSH-Message] [pool : Bytes] [offset : Natural])
                              (ssh:msg->bytes (assert self ssh:msg?) pool offset)]))))]
    [(_ id val ([field : FieldType defval ...] ...) #:case key-field)
     (with-syntax ([key-field-index (ssh-field-index #'key-field #'(field ...))])
       #'(begin (define-message-interface id val ([field : FieldType defval ...] ...))
                (hash-set! ssh-bytes->case-message-database val
                           (cons key-field-index ((inst make-hasheq Any Unsafe-SSH-Bytes->Message))))))]))

(define-syntax (define-message stx)
  (syntax-case stx [:]
    [(_ id val #:group gid (field-definition ...))
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id val (field-definition ...))
                
                (let ([database ((inst hash-ref! Symbol (HashTable Index Unsafe-SSH-Bytes->Message))
                                 ssh-bytes->shared-message-database 'gid (λ [] (make-hasheq)))])
                  (hash-set! database val unsafe-bytes->ssh:msg))))]
    [(_ id val (field-definition ...) conditions ...)
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id val (field-definition ...) conditions ...)
                (hash-set! ssh-bytes->message-database val unsafe-bytes->ssh:msg)))]))

(define-syntax (define-ssh-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ [enum:id val:nat ([field:id : FieldType defval ...] ...) conditions ...] ...)
     #'(begin (define-message enum val ([field : FieldType defval ...] ...) conditions ...) ...)]))

(define-syntax (define-ssh-shared-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ group-name:id [enum:id val:nat ([field:id : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val #:group group-name ([field : FieldType defval ...] ...)) ...)]))

(define-syntax (define-ssh-case-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ val:nat [enum:id ([field:id : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val #:case val ([field : FieldType defval ...] ...)) ...)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type Unsafe-SSH-Bytes->Message (->* (Bytes) (Index) (Values SSH-Message Natural)))
(define-type SSH-Message->Bytes (case-> [SSH-Message -> Bytes] [SSH-Message Bytes Natural -> Natural]))

(struct ssh-message ([number : Byte] [name : Symbol]) #:type-name SSH-Message)
(struct ssh-message-undefined ssh-message () #:type-name SSH-Message-Undefined)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-bytes->shared-message-database : (HashTable Symbol (HashTable Index Unsafe-SSH-Bytes->Message)) (make-hasheq))
(define ssh-bytes->case-message-database : (HashTable Index (cons Index (HashTable Any Unsafe-SSH-Bytes->Message))) (make-hasheq))
(define ssh-bytes->message-database : (HashTable Index Unsafe-SSH-Bytes->Message) (make-hasheq))
(define ssh-message->bytes-database : (HashTable Symbol SSH-Message->Bytes) (make-hasheq))
(define ssh-message-length-database : (HashTable Symbol (-> SSH-Message Natural)) (make-hasheq))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-undefined-message : (-> Byte SSH-Message-Undefined)
  (lambda [id]
    (ssh-message-undefined id 'SSH-MSG-UNDEFINED)))

(define ssh-bytes->shared-message : (-> Symbol Index (Option Unsafe-SSH-Bytes->Message))
  (lambda [gid no]
    (define maybe-db : (Option (HashTable Index Unsafe-SSH-Bytes->Message)) (hash-ref ssh-bytes->shared-message-database gid (λ [] #false)))
    (and (hash? maybe-db)
         (hash-ref maybe-db no (λ [] #false)))))
