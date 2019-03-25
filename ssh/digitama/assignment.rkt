#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))

(require "datatype.rkt")

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
    [(Index)   (list #'values #'ssh-uint32->bytes  #'ssh-bytes->uint32  #'values)]
    [(Natural) (list #'values #'ssh-uint64->bytes  #'ssh-bytes->uint64  #'values)]
    [(String)  (list #'values #'ssh-string->bytes  #'ssh-bytes->string  #'values)]
    [(Integer) (list #'values #'ssh-mpint->bytes   #'ssh-bytes->mpint   #'values)]
    [(Symbol)  (list #'values #'ssh-name->bytes    #'ssh-bytes->name    #'values)]
    [(Bytes)   (list #'values #'values             #'ssh-values         #'values)]
    [else (with-syntax* ([(TypeOf T) (syntax-e <FType>)]
                         [$type (format-id #'T "$~a" (syntax-e #'T))])
            (case (syntax-e #'TypeOf)
              [(SSH-Bytes)            (list #'values                #'values              (ssh-make-nbytes->bytes #'T) #'values)]
              [(SSH-Symbol)           (list #'$type                 #'ssh-uint32->bytes   #'ssh-bytes->uint32          #'$type)]
              [(SSH-Algorithm-Listof) (list #'ssh-algorithms->names #'ssh-namelist->bytes #'ssh-bytes->namelist        #'$type)]
              [else (if (and (free-identifier=? #'TypeOf #'Listof) (free-identifier=? #'T #'Symbol))
                        (list #'values #'ssh-namelist->bytes #'ssh-bytes->namelist #'values)
                        (raise-syntax-error 'define-ssh-message-field "invalid SSH data type" <FType>))]))]))


(define-for-syntax (ssh-message-field <declaration>)
  (define declaration (syntax-e <declaration>))
  (define <field> (car declaration))
  (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))
  (define-values (<argls> <value>)
    (syntax-case <declaration> []
      [(field FieldType) (values #'[field : FieldType] #'field)]

      ; TODO: why it fails when `defval` is using other field name?
      [(field FieldType defval) (values #'[field : (Option FieldType) #false] #'(or field defval))]
      [_ (raise-syntax-error 'define-ssh-message-field "malformed field declaration" <declaration>)]))
  (values <kw-name> <argls> <value>))

(define-syntax (define-ssh-symbols stx)
  (syntax-case stx [:]
    [(_ TypeU : Type ([enum val] ...))
     (with-syntax ([$id (format-id #'TypeU "$~a" (syntax-e #'TypeU))]
                   [(name ...) (for/list ([<enum> (in-syntax #'(enum ...))]) (ssh-typename <enum>))])
       #'(begin (define-type TypeU (U 'name ... 'enum ...))
                (define $id : (case-> [Symbol -> Type] [Integer -> TypeU])
                  (λ [v] (cond [(symbol? v) (case v [(enum name) val] ... [else 0])]
                               [else (case v [(val) 'name] ... [else (error 'TypeU "unrecognized assignment: ~a" v)])])))))]))

(define-syntax (define-ssh-algorithm stx)
  (syntax-case stx [:]
    [(_ &database ([name comments ... #:=> procedure]))
     #'(set-box! &database (cons (cons 'name procedure) (unbox &database)))]
    [(_ &database ([name comments ...]))
    #'(void)]))

(define-syntax (define-ssh-algorithm-database stx)
  (syntax-case stx [:]
    [(_ id : SSH-Type #:as Type)
     (with-syntax ([&id (format-id #'id "&~a" (syntax-e #'id))]
                   [$SSH-Type (format-id #'SSH-Type "$~a" (syntax-e #'SSH-Type))])
       #'(begin (define-type SSH-Type Type)
                
                (define &id : (Boxof (Listof (Pairof Symbol SSH-Type))) (box null))
                
                (define id : (case-> [-> (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) -> (Listof (Pairof Symbol SSH-Type))])
                  (case-lambda
                    [() (reverse (unbox &id))]
                    [(name-list) (let ([base (id)])
                                   (let filter ([algorithms : (Listof (Pairof Symbol SSH-Type)) null]
                                                [seman : (Listof Symbol) (reverse name-list)])
                                     (cond [(null? seman) algorithms]
                                           [else (let ([maybe (assq (car seman) base)]
                                                       [rest (cdr seman)])
                                                   (cond [(not maybe) (filter algorithms rest)]
                                                         [else (filter (cons maybe algorithms) rest)]))])))]))

                (define $SSH-Type : (-> (Listof Symbol) (SSH-Algorithm-Listof SSH-Type))
                  (lambda [name-list]
                    (define base : (Listof (Pairof Symbol SSH-Type)) (id))
                    (for/list : (SSH-Algorithm-Listof SSH-Type) ([name (in-list name-list)])
                      (or (assq name base)
                          (cons name #false)))))))]))

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
                    [([kw-args ...] [init-values ...])
                     (let-values ([(kw-args seulav)
                                   (for/fold ([syns null] [slav null])
                                             ([<declaration> (in-syntax #'([field FieldType defval ...] ...))])
                                     (define-values (<kw-name> <argls> <value>) (ssh-message-field <declaration>))
                                     (values (cons <kw-name> (cons <argls> syns))
                                             (cons <value> slav)))])
                       (list kw-args (reverse seulav)))]
                    [([field-ref (racket->ssh ssh->bytes bytes->ssh ssh->racket)] ...)
                     (for/list ([<field> (in-syntax #'(field ...))]
                                [<FType> (in-syntax #'(FieldType ...))])
                       (list (format-id <field> "~a-~a" (syntax-e #'ssh:msg) (syntax-e <field>))
                             (ssh-datum-pipeline <FType>)))])
       #'(begin (struct ssh:msg ssh-message ([field : FieldType] ...)
                  #:transparent #:constructor-name constructor #:type-name SSH-MSG)

                (define (make-ssh:msg kw-args ...) : SSH-MSG
                  (constructor val 'SSH-MSG init-values ...))

                (define ssh:msg->bytes : (-> SSH-MSG Bytes)
                  (lambda [self]
                    (bytes-append (bytes val)
                                  (ssh->bytes (racket->ssh (field-ref self)))
                                  ...)))

                (define unsafe-bytes->ssh:msg : (->* (Bytes) (Index) SSH-MSG)
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(offset) (+ offset 1)]
                                  [(field offset) (bytes->ssh bmsg offset)] ...)
                      (constructor val 'SSH-MSG (ssh->racket field) ...))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type Unsafe-SSH-Bytes->Message (->* (Bytes) (Index) SSH-Message))
(define-type SSH-Message->Bytes (-> SSH-Message (Option Bytes)))

(struct ssh-message ([id : Byte] [name : Symbol]) #:type-name SSH-Message)
(struct ssh-message-undefined ssh-message () #:type-name SSH-Message-Undefined)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-bytes->shared-message-database : (HashTable Symbol (HashTable Index Unsafe-SSH-Bytes->Message)) (make-hasheq))
(define ssh-bytes->message-database : (HashTable Index Unsafe-SSH-Bytes->Message) (make-hasheq))
(define ssh-message->bytes-database : (HashTable Symbol SSH-Message->Bytes) (make-hasheq))

(struct ssh-package-algorithms
  ([cipher : (Pairof Symbol SSH-Cipher)]
   [mac : (Pairof Symbol SSH-HMAC)]
   [compression : (Pairof Symbol SSH-Compression)])
  #:transparent
  #:type-name SSH-Package-Algorithms)

(define-ssh-algorithm-database ssh-kex-algorithms : SSH-Kex #:as (-> Bytes Bytes))
(define-ssh-algorithm-database ssh-hostkey-algorithms : SSH-HostKey #:as (-> Bytes Bytes))
(define-ssh-algorithm-database ssh-cipher-algorithms : SSH-Cipher #:as (-> Bytes Bytes))
(define-ssh-algorithm-database ssh-hmac-algorithms : SSH-HMAC #:as (->* (Bytes) (Natural (Option Natural)) Bytes))
(define-ssh-algorithm-database ssh-compression-algorithms : SSH-Compression #:as (-> Bytes Bytes))

(define ssh-algorithms->names : (All (a) (-> (SSH-Algorithm-Listof a) (Listof Symbol)))
  (lambda [algorithms]
    (let filter ([names : (Listof Symbol) null]
                 [smhtirogla : (SSH-Algorithm-Listof a) (reverse algorithms)])
      (cond [(null? smhtirogla) names]
            [else (let ([algorithm (car smhtirogla)]
                        [rest (cdr smhtirogla)])
                    (cond [(cdr algorithm) (filter (cons (car algorithm) names) rest)]
                          [else (filter names rest)]))]))))

(define ssh-algorithms-clean : (All (a) (-> (SSH-Algorithm-Listof a) (SSH-Algorithm-Listof* a)))
  (lambda [dirty-list]
    (let filter ([algorithms : (Listof (Pairof Symbol a)) null]
                 [smhtirogla : (SSH-Algorithm-Listof a) (reverse dirty-list)])
      (cond [(null? smhtirogla) algorithms]
            [else (let ([algorithm (car smhtirogla)]
                        [rest (cdr smhtirogla)])
                    (cond [(cdr algorithm) (filter (cons algorithm algorithms) rest)]
                          [else (filter algorithms rest)]))]))))

(define ssh-bytes->shared-message : (-> Symbol Index (Option Unsafe-SSH-Bytes->Message))
  (lambda [gid no]
    (define maybe-db : (Option (HashTable Index Unsafe-SSH-Bytes->Message)) (hash-ref ssh-bytes->shared-message-database gid (λ [] #false)))
    (and (hash? maybe-db)
         (hash-ref maybe-db no (λ [] #false))))) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-undefined-message : (-> Byte SSH-Message-Undefined)
  (lambda [id]
    (ssh-message-undefined id 'SSH-MSG-UNIMPLEMENTED)))

(define ssh-values : (SSH-Bytes->Type Bytes)
  (lambda [braw [offset 0]]
    (define end : Index (bytes-length braw))
    (values (subbytes braw offset end)
            end)))

(define ssh-hmac-none-bytes : SSH-HMAC
  (lambda [in [start 0] [end #false]]
    #""))

(define ssh-cookie : (->* () (Byte) Bytes)
  (lambda [[n 16]]
    (define cookie : Bytes (make-bytes n))

    (let pad ([rest : Nonnegative-Fixnum n])
      (define idx-8 : Fixnum (- rest 8))
      (define idx-4 : Fixnum (- rest 4))
      (define idx-1 : Fixnum (- rest 1))
      (cond [(> idx-8 0)
             (real->floating-point-bytes (random) 8 #true cookie idx-8)
             (pad idx-8)]
            [(> idx-4 0)
             (real->floating-point-bytes (random) 4 #true cookie idx-4)
             (pad idx-4)]
            [(> idx-1 0)
             (bytes-set! cookie idx-1 (random 256))
             (pad idx-1)]))
    
    cookie))