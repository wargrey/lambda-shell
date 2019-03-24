#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out))

(require racket/string)
(require racket/math)

(require racket/unsafe/ops)
(require typed/racket/unsafe)

(define-type (SSH-Bytes n) Bytes)
(define-type (SSH-Symbol ns) ns)
(define-type (SSH-Algorithm-Listof t) (Listof (Pairof Symbol (Option t))))
(define-type (SSH-Algorithm-Listof* t) (Listof (Pairof Symbol t)))
(define-type (SSH-Bytes->Type t) (->* (Bytes) (Natural) (Values t Natural)))

(unsafe-require/typed racket/base
                      [integer-bytes->integer (-> Bytes Boolean Boolean Natural Natural Index)])

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
    (define end : Natural (unsafe-fx+ offset 4))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-uint64->bytes : (-> Nonnegative-Integer Bytes)
  (lambda [u64]
    (integer->integer-bytes u64 8 #false #true)))

(define ssh-bytes->uint64 : (SSH-Bytes->Type Natural)
  (lambda [bint [offset 0]]
    (define end : Natural (unsafe-fx+ offset 8))
    (values (integer-bytes->integer bint #false #true offset end)
            end)))

(define ssh-string->bytes : (-> String Bytes)
  (lambda [utf8]
    (bytes-append (ssh-uint32->bytes (string-utf-8-length utf8))
                  (string->bytes/utf-8 utf8))))

(define ssh-bytes->string : (SSH-Bytes->Type String)
  (lambda [butf8 [offset 0]]
    (define-values (size offset++) (ssh-bytes->uint32 butf8 offset))
    (define end : Natural (unsafe-fx+ size offset++))
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
                   (cond [(and (positive? mpi) (= (bytes-ref buffer 0) #b10000000))
                          (bytes-append (ssh-uint32->bytes size+1) (bytes #x00) buffer)]
                         [(and (negative? mpi) (not (bitwise-bit-set? (bytes-ref buffer 0) 7)))
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
