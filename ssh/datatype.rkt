#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out) SSH-Datum->Bytes SSH-Bytes->Datum SSH-Void)

(require racket/string)

(require digimon/number)

(require typed/racket/unsafe)

(require "digitama/datatype.rkt")

(define-type SSH-BString Bytes)
(define-type (SSH-Bytes n) Bytes)
(define-type (SSH-Symbol ns) Symbol)
(define-type (SSH-Name-Listof t) (Listof (Pairof Symbol (Option t))))
(define-type (SSH-Name-Listof* t) (Listof (Pairof Symbol t)))
(define-type (SSH-Nameof t) (Pairof Symbol t))

(unsafe-require/typed racket/base
                      [integer-length (-> Integer Index)]
                      [integer-bytes->integer (-> Bytes Boolean Boolean Natural Natural Index)])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-boolean-length : (-> Any One)
  (lambda [bool]
    1))

(define ssh-boolean->bytes : (SSH-Datum->Bytes Any)
  (case-lambda
      [(bool) (if bool (bytes 1) (bytes 0))]
      [(bool pool) (ssh-boolean->bytes bool pool 0)]
      [(bool pool offset) (bytes-set! pool offset (if bool 1 0)) (+ offset (ssh-boolean-length bool))]))

(define ssh-bytes->boolean : (SSH-Bytes->Datum Boolean)
  (lambda [bbool [offset 0]]
    (values (not (zero? (bytes-ref bbool offset)))
            (+ offset 1))))

(define ssh-uint32-length : (-> Any 4)
  (lambda [u64]
    4))

(define ssh-uint32->bytes : (SSH-Datum->Bytes Natural)
  (case-lambda
    [(u32) (integer->integer-bytes u32 (ssh-uint32-length u32) #false #true)]
    [(u32 pool) (ssh-uint32->bytes u32 pool 0)]
    [(u32 pool offset) (let ([u32size (ssh-uint32-length u32)])
                         (integer->integer-bytes u32 u32size #false #true pool offset)
                         (+ offset u32size))]))

(define ssh-bytes->uint32 : (SSH-Bytes->Datum Index)
  (lambda [bint [offset 0]]
    (define end : Natural (+ offset 4))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-uint64-length : (-> Any 8)
  (lambda [u64]
    8))

(define ssh-uint64->bytes : (SSH-Datum->Bytes Natural)
  (case-lambda
    [(u64) (integer->integer-bytes u64 (ssh-uint64-length u64) #false #true)]
    [(u64 pool) (ssh-uint32->bytes u64 pool 0)]
    [(u64 pool offset) (let ([u64size (ssh-uint64-length u64)])
                         (integer->integer-bytes u64 u64size #false #true pool offset)
                         (+ offset u64size))]))

(define ssh-bytes->uint64 : (SSH-Bytes->Datum Natural)
  (lambda [bint [offset 0]]
    (define end : Natural (+ offset 8))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-bstring-length : (-> SSH-BString Positive-Fixnum)
  (lambda [bstr]
    (define bssize : Index (bytes-length bstr))

    (+ (ssh-uint32-length bssize)
       bssize)))

(define ssh-bstring->bytes : (SSH-Datum->Bytes SSH-BString)
  (case-lambda
    [(bstr) (bytes-append (ssh-uint32->bytes (bytes-length bstr)) bstr)]
    [(bstr pool) (ssh-bstring->bytes bstr pool 0)]
    [(bstr pool offset) (let* ([bssize (bytes-length bstr)]
                               [offset++ (ssh-uint32->bytes bssize pool offset)])
                          (bytes-copy! pool offset++ bstr 0 bssize)
                          (+ offset++ bssize))]))

(define ssh-bytes->bstring : (SSH-Bytes->Datum SSH-BString)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Natural (+ size offset++))
    (values (subbytes butf8 offset++ end)
            end)))

(define ssh-string-length : (-> String Positive-Fixnum)
  (lambda [str]
    (define ssize : Index (string-utf-8-length str))

    (+ (ssh-uint32-length ssize)
       ssize)))

(define ssh-string->bytes : (SSH-Datum->Bytes String)
  (case-lambda
    [(utf8) (ssh-bstring->bytes (string->bytes/utf-8 utf8))]
    [(utf8 pool) (ssh-bstring->bytes (string->bytes/utf-8 utf8) pool 0)]
    [(utf8 pool offset) (ssh-bstring->bytes (string->bytes/utf-8 utf8) pool offset)]))

(define ssh-bytes->string : (SSH-Bytes->Datum String)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Natural (+ size offset++))
    (values (bytes->string/utf-8 butf8 #false offset++ end)
            end)))

(define ssh-mpint-length : (-> Integer Positive-Integer)
  (lambda [mpi]
    (define bmpint-size : Index (if (= mpi 0) 0 (integer-bytes-length mpi)))

    (+ (ssh-uint32-length bmpint-size)
       bmpint-size)))

(define ssh-mpint->bytes : (SSH-Datum->Bytes Integer)
  (case-lambda
    [(mpi) (let ([bmpi (make-bytes (ssh-mpint-length mpi))]) (ssh-mpint->bytes mpi bmpi 0) bmpi)]
    [(mpi pool) (ssh-mpint->bytes mpi pool 0)]
    [(mpi pool offset)
     (cond [(= mpi 0) (ssh-uint32->bytes 0 pool offset)]
           [else (let* ([bmpint-size (integer-bytes-length mpi)]
                        [offset++ (ssh-uint32->bytes bmpint-size pool offset)])
                   (integer->network-bytes mpi 0 pool offset++)
                   (+ offset++ bmpint-size))])]))

(define ssh-bytes->mpint : (SSH-Bytes->Datum Integer)
  (lambda [bmpi [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 bmpi offset))
    (define end : Index (assert (+ size offset++) index?))
    (cond [(zero? size) (values 0 end)]
          [else (values (network-bytes->integer bmpi offset++ end) end)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-name-length : (-> Symbol Positive-Fixnum)
  (lambda [name]
    (ssh-string-length (symbol->string name))))

(define ssh-name->bytes : (SSH-Datum->Bytes Symbol)
  (case-lambda
    [(name) (ssh-string->bytes (symbol->string name))]
    [(name pool) (ssh-string->bytes (symbol->string name) pool 0)]
    [(name pool offset) (ssh-string->bytes (symbol->string name) pool offset)]))

(define ssh-bytes->name : (SSH-Bytes->Datum Symbol)
  (lambda [butf8 [offset 0]]
    (define-values (name end) (ssh-bytes->string butf8 offset))
    (values (string->symbol name) end)))

(define ssh-namelist-length : (-> (Listof Symbol) Positive-Integer)
  (lambda [names]
    (define /dev/nout : Output-Port (ssh-namelist-port names))
    (define nssize : Natural (file-position /dev/nout))

    (+ (ssh-uint32-length nssize)
       nssize)))

(define ssh-namelist->bytes : (SSH-Datum->Bytes (Listof Symbol))
  (case-lambda
    [(names) (ssh-bstring->bytes (get-output-bytes (ssh-namelist-port names) #true))]
    [(names pool) (ssh-namelist->bytes names pool 0)]
    [(names pool offset) (let ([namelist (get-output-bytes (ssh-namelist-port names) #true)])
                           (ssh-bstring->bytes namelist pool offset))]))

(define ssh-bytes->namelist : (SSH-Bytes->Datum (Listof Symbol))
  (lambda [bascii [offset 0]]
    (define-values (names end) (ssh-bytes->string bascii offset))
    (values (map string->symbol (string-split names ","))
            end)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-names->namelist : (All (a) (-> (SSH-Name-Listof a) (Listof Symbol)))
  (lambda [names]
    (let filter ([namelist : (Listof Symbol) null]
                 [seman : (SSH-Name-Listof a) (reverse names)])
      (cond [(null? seman) namelist]
            [else (let ([name (car seman)]
                        [rest (cdr seman)])
                    (cond [(cdr name) (filter (cons (car name) namelist) rest)]
                          [else (filter namelist rest)]))]))))

(define ssh-names-clean : (All (a) (-> (SSH-Name-Listof a) (SSH-Name-Listof* a)))
  (lambda [dirty-list]
    (let filter ([names : (SSH-Name-Listof* a) null]
                 [seman : (SSH-Name-Listof a) (reverse dirty-list)])
      (cond [(null? seman) names]
            [else (let ([name (car seman)]
                        [rest (cdr seman)])
                    (cond [(cdr name) (filter (cons name names) rest)]
                          [else (filter names rest)]))]))))

(define ssh-names-remove : (All (a) (-> Symbol (SSH-Name-Listof* a) (SSH-Name-Listof* a)))
  (lambda [n namebase]
    (let filter ([names : (SSH-Name-Listof* a) null]
                 [seman : (SSH-Name-Listof* a) (reverse namebase)])
      (cond [(null? seman) names]
            [else (let ([name (car seman)]
                        [rest (cdr seman)])
                    (cond [(eq? n (car name)) (filter names rest)]
                          [else (filter (cons name names) rest)]))]))))
