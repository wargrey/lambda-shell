#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out) SSH-Bytes->Type)
(provide (for-syntax ssh-datum-pipeline))

(require racket/string)

(require racket/unsafe/ops)
(require typed/racket/unsafe)

(require "digitama/datatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-type SSH-BString Bytes)
(define-type (SSH-Bytes n) Bytes)
(define-type (SSH-Symbol ns) ns)
(define-type (SSH-Algorithm-Listof t) (Listof (Pairof Symbol (Option t))))
(define-type (SSH-Algorithm-Listof* t) (Listof (Pairof Symbol t)))

(unsafe-require/typed racket/base
                      [integer-bytes->integer (-> Bytes Boolean Boolean Natural Natural Index)])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

(define-syntax (define-ssh-struct stx)
  (syntax-case stx [:]
    [(_ id : ID ([field : FieldType defval ...] ...))
     (with-syntax* ([make-id (format-id #'id "make-~a" (syntax-e #'id))]
                    [id->bytes (format-id #'id "~a->bytes" (syntax-e #'id))]
                    [bytes->id (format-id #'id "bytes->~a" (syntax-e #'id))]
                    [bytes->id* (format-id #'id "bytes->~a*" (syntax-e #'id))]
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
                       (list (format-id <field> "~a-~a" (syntax-e #'id) (syntax-e <field>))
                             (ssh-datum-pipeline 'define-ssh-struct <FType>)))])
       #'(begin (struct id ([field : FieldType] ...) #:transparent #:type-name ID)

                (define (make-id kw-args ...) : ID
                  (id init-values ...))

                (define id->bytes : (-> ID Bytes)
                  (lambda [self]
                    (bytes-append (ssh->bytes (field-ref self))
                                  ...)))

                (define bytes->id : (->* (Bytes) (Index) (Values ID Nonnegative-Fixnum))
                  (lambda [bmsg [offset 0]]
                    (let*-values ([(field offset) (bytes->ssh bmsg offset)] ...)
                      (values (id field ...) offset))))

                (define bytes->id* : (->* (Bytes) (Index) ID)
                  (lambda [bmsg [offset 0]]
                    (define-values (message end-index) (bytes->id bmsg offset))
                    message))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-boolean->bytes : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes 1) (bytes 0))))

(define ssh-bytes->boolean : (SSH-Bytes->Type Boolean)
  (lambda [bbool [offset 0]]
    (values (not (zero? (bytes-ref bbool offset)))
            (unsafe-fx+ offset 1))))

(define ssh-uint32->bytes : (-> Index Bytes)
  (lambda [u32]
    (integer->integer-bytes u32 4 #false #true)))

(define ssh-bytes->uint32 : (SSH-Bytes->Type Index)
  (lambda [bint [offset 0]]
    (define end : Positive-Fixnum (unsafe-fx+ offset 4))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-uint64->bytes : (-> Nonnegative-Integer Bytes)
  (lambda [u64]
    (integer->integer-bytes u64 8 #false #true)))

(define ssh-bytes->uint64 : (SSH-Bytes->Type Natural)
  (lambda [bint [offset 0]]
    (define end : Positive-Fixnum (unsafe-fx+ offset 8))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-bstring->bytes : (-> SSH-BString Bytes)
  (lambda [bs]
    (bytes-append (ssh-uint32->bytes (bytes-length bs)) bs)))

(define ssh-bytes->bstring : (SSH-Bytes->Type SSH-BString)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Nonnegative-Fixnum (unsafe-fx+ size offset++))
    (values (subbytes butf8 offset++ end)
            end)))

(define ssh-string->bytes : (-> String Bytes)
  (lambda [utf8]
    (ssh-bstring->bytes (string->bytes/utf-8 utf8))))

(define ssh-bytes->string : (SSH-Bytes->Type String)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Nonnegative-Fixnum (unsafe-fx+ size offset++))
    (values (bytes->string/utf-8 butf8 #false offset++ end)
            end)))

(define ssh-mpint->bytes : (-> Integer Bytes)
   (lambda [mpi]
     (cond [(zero? mpi) (ssh-uint32->bytes 0)]
           [else (let* ([buffer : Bytes (make-bytes (quotient (unsafe-fx+ (integer-length mpi) 7) 8))]
                        [size : Index (bytes-length buffer)]
                        [size+1 : Index (assert (+ size 1) index?)])
                   (for ([idx (in-range size)])
                     (unsafe-bytes-set! buffer idx (bitwise-and (arithmetic-shift mpi (unsafe-fx* (unsafe-fx- size (unsafe-fx+ idx 1)) -8)) #xFF)))
                   (cond [(and (positive? mpi) (bitwise-bit-set? (unsafe-bytes-ref buffer 0) 7))
                          (bytes-append (ssh-uint32->bytes size+1) (bytes #x00) buffer)]
                         [(and (negative? mpi) (not (bitwise-bit-set? (unsafe-bytes-ref buffer 0) 7)))
                          (bytes-append (ssh-uint32->bytes size+1) (bytes #xFF) buffer)]
                         [else (bytes-append (ssh-uint32->bytes size) buffer)]))])))

(define ssh-bytes->mpint : (SSH-Bytes->Type Integer)
  (lambda [bmpi [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 bmpi offset))
    (define end : Nonnegative-Fixnum (unsafe-fx+ size offset++))
    (cond [(zero? size) (values 0 end)]
          [else (let bytes->mpint ([idx : Fixnum (unsafe-fx+ offset++ 1)]
                                   [mpint : Integer (let ([mpi0 (bytes-ref bmpi offset++)])
                                                      (if (> mpi0 #b01111111) (- mpi0 #x100) mpi0))])
                  (cond [(zero? (unsafe-fx- idx end)) (values mpint end)]
                        [else (bytes->mpint (unsafe-fx+ idx 1)
                                            (bitwise-ior (arithmetic-shift mpint 8)
                                                         (bytes-ref bmpi idx)))]))])))

(define ssh-name->bytes : (-> Symbol Bytes)
  (lambda [name]
    (ssh-string->bytes (symbol->string name))))

(define ssh-bytes->name : (SSH-Bytes->Type Symbol)
  (lambda [butf8 [offset 0]]
    (define-values (name end) (ssh-bytes->string butf8 offset))
    (values (string->symbol name) end)))

(define ssh-namelist->bytes : (-> (Listof Symbol) Bytes)
  (lambda [names]
    (ssh-string->bytes (string-join (map symbol->string names) ","))))

(define ssh-bytes->namelist : (SSH-Bytes->Type (Listof Symbol))
  (lambda [bascii [offset 0]]
    (define-values (names end) (ssh-bytes->string bascii offset))
    (values (map string->symbol (string-split names ","))
            end)))

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
