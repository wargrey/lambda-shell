#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide unsafe-struct*-ref)
(provide (for-syntax ssh-typename ssh-typeid))

(require racket/unsafe/ops)

(require "conditional-message.rkt")
(require "datatype.rkt")
(require "../datatype.rkt")

(require/typed "conditional-message.rkt"
               [ssh-case-message-field-database (HashTable Symbol (Pairof Index (Listof (List* Symbol (Listof Any)))))])

(require (for-syntax racket/base))
(require (for-syntax racket/string))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))
(require (for-syntax syntax/parse))

(require (for-syntax "conditional-message.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax ssh-case-message-field-database:1 (make-hasheq))

(define-for-syntax (ssh-typename <id>)
  (format-id <id> "~a" (string-replace (symbol->string (syntax-e <id>)) "_" "-")))

(define-for-syntax (ssh-typeid <id>)
  (format-id <id> "~a" (string-replace (string-downcase (symbol->string (syntax-e <id>))) #px"[_-]" ":")))

(define-for-syntax (ssh-message-constructors <ssh:msg>)
  (list (format-id <ssh:msg> "~a" (gensym 'ssh:msg:))
        (format-id <ssh:msg> "make-~a" (syntax-e <ssh:msg>))))

(define-for-syntax (ssh-message-procedures <id>)
  (define <ssh:msg> (ssh-typeid <id>))
  (define ssh:msg (syntax-e <ssh:msg>))
  
  (list* <ssh:msg>
         (map (λ [fmt] (format-id <ssh:msg> fmt ssh:msg))
              (list "~a?" "~a-length" "~a->bytes" "unsafe-bytes->~a" "unsafe-bytes->~a*"))))

(define-for-syntax (ssh-message-arguments <field-declarations>)
  (define-values (kw-args seulav)
    (for/fold ([syns null] [slav null])
              ([<declaration> (in-syntax <field-declarations>)])
      (define-values (<kw-name> <argls> <value>) (ssh-struct-field <declaration>))
      (values (cons <kw-name> (cons <argls> syns))
              (cons <value> slav))))
  (list kw-args (reverse seulav)))

(define-for-syntax (ssh-message-field-transforms ssh:msg <fields> <FieldTypes>)
  (for/list ([<field> (in-syntax <fields>)]
             [<FType> (in-syntax <FieldTypes>)])
    (list (format-id <field> "~a-~a" ssh:msg (syntax-e <field>))
          (ssh-datum-pipeline 'define-ssh-messages <FType>))))

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
    [(_ id n ([field : FieldType defval ...] ...))
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [(ssh:msg ssh:msg? ssh:msg-length ssh:msg->bytes unsafe-bytes->ssh:msg unsafe-bytes->ssh:msg*) (ssh-message-procedures #'id)]
                    [(constructor make-ssh:msg) (ssh-message-constructors #'ssh:msg)]
                    [([kw-args ...] [init-values ...]) (ssh-message-arguments #'([field FieldType defval ...] ...))]
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket ssh-datum-length)] ...)
                     (ssh-message-field-transforms (syntax-e #'ssh:msg) #'(field ...) #'(FieldType ...))])
       #'(begin (struct ssh:msg ssh-message ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor #:type-name SSH-MSG)

                (define (make-ssh:msg kw-args ...) : SSH-MSG
                  (constructor n 'SSH-MSG init-values ...))

                (define ssh:msg-length : (-> SSH-MSG Positive-Integer)
                  (lambda [self]
                    (+ 1 ; message number
                       (ssh-datum-length (racket->ssh (field-ref self)))
                       ...)))

                (define ssh:msg->bytes : (SSH-Datum->Bytes SSH-MSG)
                  (case-lambda
                    [(self) (bytes-append (bytes n) (ssh->bytes (racket->ssh (field-ref self))) ...)]
                    [(self pool) (ssh:msg->bytes self pool 0)]
                    [(self pool offset) (let* ([offset++ (+ offset 1)]
                                               [offset++ (ssh->bytes (racket->ssh (field-ref self)) pool offset++)] ...)
                                          (bytes-set! pool offset n)
                                          offset++)]))

                (define unsafe-bytes->ssh:msg : (->* (Bytes) (Index) (Values SSH-MSG Natural))
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(offset) (+ offset 1)]
                                  [(field offset) (bytes->ssh bmsg offset)] ...)
                      (values (constructor n 'SSH-MSG (ssh->racket field) ...)
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
    [(_ id n #:parent parent ([pield : PieldType pefval ...] ...) ([field : FieldType defval ...] ...))
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [(ssh:msg ssh:msg? ssh:msg-length ssh:msg->bytes unsafe-bytes->ssh:msg unsafe-bytes->ssh:msg*) (ssh-message-procedures #'id)]
                    [(pssh:msg _ pssh:msg-length pssh:msg->bytes _ _) (ssh-message-procedures #'parent)]
                    [(constructor make-ssh:msg) (ssh-message-constructors #'ssh:msg)]
                    [([kw-args ...] [init-values ...]) (ssh-message-arguments #'([pield PieldType pefval ...] ... [field FieldType defval ...] ...))]
                    [([_ (_ _ parent-bytes->ssh parent-ssh->racket _)] ...) (ssh-message-field-transforms (syntax-e #'pssh:msg) #'(pield ...) #'(PieldType ...))]
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket ssh-datum-length)] ...)
                     (ssh-message-field-transforms (syntax-e #'ssh:msg) #'(field ...) #'(FieldType ...))])
       #'(begin (struct ssh:msg pssh:msg ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor #:type-name SSH-MSG)

                (define (make-ssh:msg kw-args ...) : SSH-MSG
                  (constructor n 'SSH-MSG init-values ...))

                (define ssh:msg-length : (-> SSH-MSG Positive-Integer)
                  (lambda [self]
                    (+ (pssh:msg-length self)
                       (ssh-datum-length (racket->ssh (field-ref self)))
                       ...)))

                (define ssh:msg->bytes : (SSH-Datum->Bytes SSH-MSG)
                  (case-lambda
                    [(self) (bytes-append (pssh:msg->bytes self) (ssh->bytes (racket->ssh (field-ref self))) ...)]
                    [(self pool) (ssh:msg->bytes self pool 0)]
                    [(self pool offset) (let* ([offset++ (pssh:msg->bytes self pool offset)]
                                               [offset++ (ssh->bytes (racket->ssh (field-ref self)) pool offset++)] ...)
                                          offset++)]))

                (define unsafe-bytes->ssh:msg : (->* (Bytes) (Index) (Values SSH-MSG Natural))
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(offset) (+ offset 1)]
                                  [(pield offset) (parent-bytes->ssh bmsg offset)] ...
                                  [(field offset) (bytes->ssh bmsg offset)] ...)
                      (values (constructor n 'SSH-MSG (parent-ssh->racket pield) ... (ssh->racket field) ...)
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
    [(_ id n ([field : FieldType defval ...] ...) #:case key-field)
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [key-field-index (ssh-field-index #'key-field #'(field ...) 0)]
                    [field-infos (ssh-case-message-fields #'n #'(field ...) #'(FieldType ...) #'([defval ...] ...) (syntax-e #'key-field-index))]
                    [_ (hash-set! ssh-case-message-field-database (syntax-e #'SSH-MSG) (syntax->datum #'field-infos))])
       #'(begin (define-message-interface id n ([field : FieldType defval ...] ...))

                (hash-set! ssh-bytes->case-message-database 'SSH-MSG
                           (cons key-field-index ((inst make-hasheq Any Unsafe-SSH-Bytes->Message))))
                
                (hash-set! ssh-case-message-field-database 'SSH-MSG 'field-infos)))]
    [(_ id n #:parent parent ([pield : PieldType pefval ...] ...) ([field : FieldType defval ...] ...) #:case key-field)
     (with-syntax* ([SSH-MSG (ssh-typename #'id)]
                    [key-field-index (ssh-field-index #'key-field #'(field ...) (length (syntax->list #'(pield ...))))]
                    [field-infos (ssh-case-message-fields #'n #'(pield ... field ...) #'(PieldType ... FieldType ...) #'([pefval ...] ... [defval ...] ...)
                                                          (syntax-e #'key-field-index))]
                    [_ (hash-set! ssh-case-message-field-database (syntax-e #'SSH-MSG) (syntax->datum #'field-infos))])
       #'(begin (define-message-interface id n #:parent parent ([pield : PieldType pefval ...] ...) ([field : FieldType defval ...] ...))

                (hash-set! ssh-bytes->case-message-database 'SSH-MSG
                           (cons key-field-index ((inst make-hasheq Any Unsafe-SSH-Bytes->Message))))
                
                (hash-set! ssh-case-message-field-database 'SSH-MSG 'field-infos)))]))

(define-syntax (define-message stx)
  (syntax-case stx [:]
    [(_ id n #:group gid (field-definition ...))
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id n (field-definition ...))
                
                (let ([database ((inst hash-ref! Symbol (HashTable Index Unsafe-SSH-Bytes->Message))
                                 ssh-bytes->shared-message-database 'gid (λ [] (make-hasheq)))])
                  (hash-set! database n unsafe-bytes->ssh:msg))))]
    [(_ id n (field-definition ...) conditions ...)
     (with-syntax* ([ssh:msg (ssh-typeid #'id)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))])
       #'(begin (define-message-interface id n (field-definition ...) conditions ...)

                (unless (hash-has-key? ssh-bytes->message-database n)
                  (hash-set! ssh-bytes->message-database n unsafe-bytes->ssh:msg))))]
    [(_ id n #:parent parent (parent-field-definition ...) (field-definition ...) conditions ...)
     #'(begin (define-message-interface id n #:parent parent
                (parent-field-definition ...) (field-definition ...) conditions ...)

                #| messages that have a parent have already had their number registered |#)]))

(define-syntax (define-ssh-case-message stx)
  (syntax-parse stx #:literals [:]
    [(_ id id-suffix case-value ([field:id : FieldType defval ...] ...) conditions ...)
     (with-syntax* ([PSSH-MSG (ssh-typename #'id)]
                    [SSH-MSG (format-id #'case-value "~a_~a" (syntax-e #'id) (syntax->datum #'id-suffix))]
                    [ssh:msg (ssh-typeid #'SSH-MSG)]
                    [unsafe-bytes->ssh:msg (format-id #'ssh:msg "unsafe-bytes->~a" (syntax-e #'ssh:msg))]
                    [(n [pield-field PieldType smart_defval ...] ...)
                     (ssh-case-message-shared-fields ssh-case-message-field-database #'PSSH-MSG #'case-value)])
       #'(begin (define-message SSH-MSG n #:parent PSSH-MSG
                  ([pield-field : PieldType smart_defval ...] ...)
                  ([field : FieldType defval ...] ...)
                  conditions ...)

                (hash-set! (cdr (hash-ref ssh-bytes->case-message-database 'PSSH-MSG))
                           case-value unsafe-bytes->ssh:msg)))]))

(define-syntax (define-ssh-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ [enum:id n:nat ([field:id : FieldType defval ...] ...) conditions ...] ...)
     #'(begin (define-message enum n ([field : FieldType defval ...] ...) conditions ...) ...)]))

(define-syntax (define-ssh-shared-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ group-name:id [enum:id n:nat ([field:id : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum n #:group group-name ([field : FieldType defval ...] ...)) ...)]))

(define-syntax (define-ssh-case-messages stx)
  (syntax-parse stx #:literals [:]
    [(_ id [id-suffix case-value ([field:id : FieldType defval ...] ...) conditions ...] ...)
     #'(begin (define-ssh-case-message id id-suffix case-value ([field : FieldType defval ...] ...) conditions ...)
              ...)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type Unsafe-SSH-Bytes->Message (->* (Bytes) (Index) (Values SSH-Message Natural)))
(define-type SSH-Message->Bytes (case-> [SSH-Message -> Bytes] [SSH-Message Bytes Natural -> Natural]))

(struct ssh-message ([number : Byte] [name : Symbol]) #:type-name SSH-Message)
(struct ssh-message-undefined ssh-message () #:type-name SSH-Message-Undefined)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-bytes->shared-message-database : (HashTable Symbol (HashTable Index Unsafe-SSH-Bytes->Message)) (make-hasheq))
(define ssh-bytes->case-message-database : (HashTable Symbol (cons Index (HashTable Any Unsafe-SSH-Bytes->Message))) (make-hasheq))
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
