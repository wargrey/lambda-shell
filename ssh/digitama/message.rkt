#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide (for-syntax ssh-typename ssh-typeid))

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

(define-for-syntax (ssh-make-nbytes->bytes <n>)
  #`(λ [[braw : Bytes] [offset : Natural 0]] : (Values Bytes Nonnegative-Fixnum)
      (let ([end (unsafe-fx+ offset #,(syntax-e <n>))])
        (values (subbytes braw offset end) end))))

(define-for-syntax (ssh-datum-pipeline func <FType>)
  (case (syntax->datum <FType>)
    [(Boolean)     (list #'values #'ssh-boolean->bytes #'ssh-bytes->boolean #'values)]
    [(Index)       (list #'values #'ssh-uint32->bytes  #'ssh-bytes->uint32  #'values)]
    [(Natural)     (list #'values #'ssh-uint64->bytes  #'ssh-bytes->uint64  #'values)]
    [(String)      (list #'values #'ssh-string->bytes  #'ssh-bytes->string  #'values)]
    [(SSH-BString) (list #'values #'ssh-bstring->bytes #'ssh-bytes->bstring #'values)]
    [(Integer)     (list #'values #'ssh-mpint->bytes   #'ssh-bytes->mpint   #'values)]
    [(Symbol)      (list #'values #'ssh-name->bytes    #'ssh-bytes->name    #'values)]
    [(Bytes)       (list #'values #'values             #'ssh-values         #'values)]
    [else (with-syntax* ([(TypeOf T) (syntax-e <FType>)]
                         [$type (format-id #'T "$~a" (syntax-e #'T))])
            (case (syntax-e #'TypeOf)
              [(SSH-Bytes)            (list #'values                #'values              (ssh-make-nbytes->bytes #'T) #'values)]
              [(SSH-Symbol)           (list #'$type                 #'ssh-uint32->bytes   #'ssh-bytes->uint32          #'$type)]
              [(SSH-Algorithm-Listof) (list #'ssh-algorithms->names #'ssh-namelist->bytes #'ssh-bytes->namelist        #'$type)]
              [else (if (and (free-identifier=? #'TypeOf #'Listof) (free-identifier=? #'T #'Symbol))
                        (list #'values #'ssh-namelist->bytes #'ssh-bytes->namelist #'values)
                        (raise-syntax-error func "invalid SSH data type" <FType>))]))]))

(define-syntax (define-message-interface stx)
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

                (define SSH:MSG->bytes : (-> SSH-Message (Option Bytes))
                  (lambda [self]
                    (and (ssh:msg? self)
                         (ssh:msg->bytes self))))
                
                (hash-set! ssh-message->bytes-database 'SSH-MSG SSH:MSG->bytes)))]))

(define-syntax (define-message stx)
  (syntax-case stx [:]
    [(_ id val #:group gid (field-definition ...))
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id val (field-definition ...))
                
                (let ([database ((inst hash-ref! Symbol (HashTable Index Unsafe-SSH-Bytes->Message))
                                 ssh-bytes->shared-message-database 'gid (λ [] (make-hasheq)))])
                  (hash-set! database val unsafe-bytes->ssh:msg))))]
    [(_ id val (field-definition ...))
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id val (field-definition ...))
                (hash-set! ssh-bytes->message-database val unsafe-bytes->ssh:msg)))]))

(define-syntax (define-ssh-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ [enum:id val:nat ([field:id : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val ([field : FieldType defval ...] ...)) ...)]))

(define-syntax (define-ssh-shared-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ group-name:id [enum:id val:nat ([field:id : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val #:group group-name ([field : FieldType defval ...] ...)) ...)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type Unsafe-SSH-Bytes->Message (->* (Bytes) (Index) (Values SSH-Message Natural)))
(define-type SSH-Message->Bytes (-> SSH-Message (Option Bytes)))

(struct ssh-message ([id : Byte] [name : Symbol]) #:type-name SSH-Message)
(struct ssh-message-undefined ssh-message () #:type-name SSH-Message-Undefined)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-bytes->shared-message-database : (HashTable Symbol (HashTable Index Unsafe-SSH-Bytes->Message)) (make-hasheq))
(define ssh-bytes->message-database : (HashTable Index Unsafe-SSH-Bytes->Message) (make-hasheq))
(define ssh-message->bytes-database : (HashTable Symbol SSH-Message->Bytes) (make-hasheq))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-undefined-message : (-> Byte SSH-Message-Undefined)
  (lambda [id]
    (ssh-message-undefined id 'SSH-MSG-UNDEFINED)))

(define ssh-bytes->shared-message : (-> Symbol Index (Option Unsafe-SSH-Bytes->Message))
  (lambda [gid no]
    (define maybe-db : (Option (HashTable Index Unsafe-SSH-Bytes->Message)) (hash-ref ssh-bytes->shared-message-database gid (λ [] #false)))
    (and (hash? maybe-db)
         (hash-ref maybe-db no (λ [] #false)))))
