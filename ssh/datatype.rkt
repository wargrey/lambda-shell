#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out) SSH-Bytes->Datum)

(require racket/string)

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
           [else (let* ([bmpint : Bytes (make-bytes (quotient (+ (integer-length mpi) 7) 8))]
                        [size : Index (bytes-length bmpint)])
                   (let mpint->bytes ([sth : Nonnegative-Fixnum size]
                                      [mpint : Integer mpi])
                     (define sth-8 : Fixnum (- sth 8))
                     (define sth-4 : Fixnum (- sth 4))
                     (define sth-1 : Fixnum (- sth 1))

                     (cond [(>= sth-8 0)
                            (integer->integer-bytes (bitwise-and mpint #xFFFFFFFFFFFFFFFF) 8 #false #true bmpint sth-8)
                            (mpint->bytes sth-8 (arithmetic-shift mpint -64))]
                           [(>= sth-4 0)
                            (integer->integer-bytes (bitwise-and mpint #xFFFFFFFF) 4 #false #true bmpint sth-4)
                            (mpint->bytes sth-4 (arithmetic-shift mpint -32))]
                           [(>= sth-1 0)
                            (bytes-set! bmpint sth-1 (bitwise-and mpint #xFF))
                            (mpint->bytes sth-1 (arithmetic-shift mpint -8))]))
                   
                   (cond [(and (positive? mpi) (bitwise-bit-set? (bytes-ref bmpint 0) 7))
                          (bytes-append (ssh-uint32->bytes (+ size 1)) (bytes #x00) bmpint)]
                         [(and (negative? mpi) (not (bitwise-bit-set? (bytes-ref bmpint 0) 7)))
                          (bytes-append (ssh-uint32->bytes (+ size 1)) (bytes #xFF) bmpint)]
                         [else (bytes-append (ssh-uint32->bytes size) bmpint)]))])))

(define ssh-bytes->mpint : (SSH-Bytes->Datum Integer)
  (lambda [bmpi [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 bmpi offset))
    (define end : Index (assert (+ size offset++) index?))
    (cond [(zero? size) (values 0 end)]
          [else (let bytes->mpint ([idx : Index (assert offset++ index?)]
                                   [mpint : Integer (if (> (bytes-ref bmpi offset++) #b01111111) -1 0)])
                  (define idx+8 : Nonnegative-Fixnum (+ idx 8))
                  (define idx+4 : Nonnegative-Fixnum (+ idx 4))
                  (define idx+1 : Nonnegative-Fixnum (+ idx 1))

                  (cond [(<= idx+8 end) (bytes->mpint idx+8 (bitwise-ior (arithmetic-shift mpint 64) (integer-bytes->integer bmpi #false #true idx idx+8)))]
                        [(<= idx+4 end) (bytes->mpint idx+4 (bitwise-ior (arithmetic-shift mpint 32) (integer-bytes->integer bmpi #false #true idx idx+4)))]
                        [(<= idx+1 end) (bytes->mpint idx+1 (bitwise-ior (arithmetic-shift mpint 8) (bytes-ref bmpi idx)))]
                        [else (values mpint end)]))])))

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
