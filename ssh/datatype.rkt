#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out) SSH-Bytes->Datum)

(require racket/string)

(require digimon/number)

(require typed/racket/unsafe)

(require "digitama/datatype.rkt")

(define-type SSH-BString Bytes)
(define-type (SSH-Bytes n) Bytes)
(define-type (SSH-Symbol ns) ns)
(define-type (SSH-Algorithm-Listof t) (Listof (Pairof Symbol (Option t))))
(define-type (SSH-Algorithm-Listof* t) (Listof (Pairof Symbol t)))

(unsafe-require/typed racket/base
                      [integer-length (-> Integer Index)]
                      [integer-bytes->integer (-> Bytes Boolean Boolean Natural Natural Index)])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-boolean->bytes : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes 1) (bytes 0))))

(define ssh-bytes->boolean : (SSH-Bytes->Datum Boolean)
  (lambda [bbool [offset 0]]
    (values (not (zero? (bytes-ref bbool offset)))
            (+ offset 1))))

(define ssh-uint32->bytes : (-> Natural Bytes)
  (lambda [u32]
    (integer->integer-bytes u32 4 #false #true)))

(define ssh-bytes->uint32 : (SSH-Bytes->Datum Index)
  (lambda [bint [offset 0]]
    (define end : Natural (+ offset 4))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-uint64->bytes : (-> Natural Bytes)
  (lambda [u64]
    (integer->integer-bytes u64 8 #false #true)))

(define ssh-bytes->uint64 : (SSH-Bytes->Datum Natural)
  (lambda [bint [offset 0]]
    (define end : Natural (+ offset 8))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-bstring->bytes : (-> SSH-BString Bytes)
  (lambda [bs]
    (bytes-append (ssh-uint32->bytes (bytes-length bs)) bs)))

(define ssh-bytes->bstring : (SSH-Bytes->Datum SSH-BString)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Natural (+ size offset++))
    (values (subbytes butf8 offset++ end)
            end)))

(define ssh-string->bytes : (-> String Bytes)
  (lambda [utf8]
    (ssh-bstring->bytes (string->bytes/utf-8 utf8))))

(define ssh-bytes->string : (SSH-Bytes->Datum String)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Natural (+ size offset++))
    (values (bytes->string/utf-8 butf8 #false offset++ end)
            end)))

(define ssh-mpint->bytes : (-> Integer Bytes)
  (lambda [mpi]
    (cond [(zero? mpi) (ssh-uint32->bytes 0)]
          [else (let* ([bmpint : Bytes (integer->network-bytes mpi)]
                       [size : Index (bytes-length bmpint)])
                  (cond [(and (positive? mpi) (>= (bytes-ref bmpint 0) #b10000000))
                         (bytes-append (ssh-uint32->bytes (+ size 1)) (bytes #x00) bmpint)]
                        [(and (negative? mpi) (< (bytes-ref bmpint 0) #b10000000))
                         (bytes-append (ssh-uint32->bytes (+ size 1)) (bytes #xFF) bmpint)]
                        [else (bytes-append (ssh-uint32->bytes size) bmpint)]))])))

(define ssh-bytes->mpint : (SSH-Bytes->Datum Integer)
  (lambda [bmpi [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 bmpi offset))
    (define end : Index (assert (+ size offset++) index?))
    (cond [(zero? size) (values 0 end)]
          [else (values (network-bytes->integer bmpi offset++ end) end)])))

(define ssh-name->bytes : (-> Symbol Bytes)
  (lambda [name]
    (ssh-string->bytes (symbol->string name))))

(define ssh-bytes->name : (SSH-Bytes->Datum Symbol)
  (lambda [butf8 [offset 0]]
    (define-values (name end) (ssh-bytes->string butf8 offset))
    (values (string->symbol name) end)))

(define ssh-namelist->bytes : (-> (Listof Symbol) Bytes)
  (lambda [names]
    (ssh-string->bytes (string-join (map symbol->string names) ","))))

(define ssh-bytes->namelist : (SSH-Bytes->Datum (Listof Symbol))
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
