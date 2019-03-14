#lang typed/racket/base

;;; http://tools.ietf.org/html/rfc4251#section-5

(provide (all-defined-out))

(require racket/string)
(require racket/math)

(define-type UInt32 Index)
(define-type UInt64 Natural)
(define-type MPInteger Integer)

(define ssh-boolean->bytes : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes 1) (bytes 0))))

(define ssh-bytes->boolean : (-> Bytes [#:offset Natural] Boolean)
  (lambda [bbool #:offset [offset 0]]
    (not (zero? (bytes-ref bbool offset)))))

(define ssh-uint32->bytes : (-> UInt32 Bytes)
  (lambda [u32]
    (integer->integer-bytes u32 4 #false #true)))

(define ssh-bytes->uint32 : (-> Bytes [#:offset Natural] UInt32)
  (lambda [bint #:offset [offset 0]]
    (cast (integer-bytes->integer bint #false #true offset (+ offset 4)) UInt32)))

(define ssh-uint64->bytes : (-> Nonnegative-Integer Bytes)
  (lambda [u64]
    (integer->integer-bytes u64 8 #false #true)))

(define ssh-bytes->uint64 : (-> Bytes [#:offset Natural] Nonnegative-Integer)
  (lambda [bint #:offset [offset 0]]
    (cast (integer-bytes->integer bint #false #true offset (+ offset 8)) UInt32)))

(define ssh-string->bytes : (-> String Bytes)
  (lambda [utf8]
    (bytes-append (ssh-uint32->bytes (string-utf-8-length utf8))
                  (string->bytes/utf-8 utf8))))

(define ssh-bytes->string : (-> Bytes [#:offset Natural] String)
  (lambda [butf8 #:offset [offset 0]]
    (bytes->string/utf-8 butf8 #false (+ offset 4) (+ offset 4 (ssh-bytes->uint32 butf8 #:offset offset)))))

(define ssh-mpint->bytes : (-> Integer Bytes)
   (lambda [mpi]
     (cond [(zero? mpi) (ssh-uint32->bytes 0)]
           [else (let* ([buffer : Bytes (make-bytes (quotient (+ (integer-length mpi) 7) 8))]
                        [size : Index (bytes-length buffer)]
                        [size+1 : Index (assert (+ size 1) index?)])
                   (for ([idx : Integer (in-range size)])
                     (bytes-set! buffer idx (bitwise-and (arithmetic-shift mpi (* (- size idx 1) -8)) #xFF)))
                   (cond [(and (positive? mpi) (= (bytes-ref buffer 0) #b10000000))
                          (bytes-append (ssh-uint32->bytes size+1) (bytes #x00) buffer)]
                         [(and (negative? mpi) (not (bitwise-bit-set? (bytes-ref buffer 0) 7)))
                          (bytes-append (ssh-uint32->bytes size+1) (bytes #xFF) buffer)]
                         [else (bytes-append (ssh-uint32->bytes size) buffer)]))])))

(define ssh-bytes->mpint : (-> Bytes [#:offset Natural] Integer)
  (lambda [bmpi #:offset [offset 0]]
    (define len : Integer (ssh-bytes->uint32 bmpi #:offset offset))
    (cond [(zero? len) 0]
          [else (let bytes->mpint ([idx : Integer (+ offset 4 1)]
                                   [mpint : Integer (let ([mpi0 : Byte (bytes-ref bmpi (+ offset 4))])
                                                      (if (> mpi0 #b01111111) (- mpi0 #x100) mpi0))])
                  (cond [(zero? (- idx len offset 4)) mpint]
                        [else (bytes->mpint (add1 idx)
                                            (bitwise-ior (arithmetic-shift mpint 8)
                                                         (bytes-ref bmpi idx)))]))])))

(define ssh-namelist->bytes : (-> (Listof Symbol) Bytes)
  (lambda [names]
    (ssh-string->bytes (string-join (map symbol->string names) ","))))

(define ssh-bytes->namelist : (-> Bytes [#:offset Natural] (Listof Symbol))
  (lambda [bascii #:offset [offset 0]]
    (map string->symbol (string-split (ssh-bytes->string bascii #:offset offset) ","))))
