#lang typed/racket/base

(provide (all-defined-out))

(require math/number-theory)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-cookie : (->* () (Byte) Bytes)
  (lambda [[n 16]]
    (define cookie : Bytes (make-bytes n))

    (let pad ([rest : Nonnegative-Fixnum n])
      (define idx-8 : Fixnum (- rest 8))
      (define idx-4 : Fixnum (- rest 4))
      (define idx-1 : Fixnum (- rest 1))

      (cond [(>= idx-8 0)
             (real->floating-point-bytes (random) 8 #true cookie idx-8)
             (pad idx-8)]
            [(>= idx-4 0)
             (real->floating-point-bytes (random) 4 #true cookie idx-4)
             (pad idx-4)]
            [(>= idx-1 0)
             (bytes-set! cookie idx-1 (random 256))
             (pad idx-1)]))
    
    cookie))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define random-odd-prime : (->* (Index) (Positive-Byte) Positive-Integer)
  (lambda [nbits [block-bits 30]]
    (define bit : Integer (remainder (- nbits 1) 8))
    (define head-byte : Byte (bitwise-and (arithmetic-shift 3 (- bit 1)) #xFF))
    (define rbignum : Natural (random-nbits nbits block-bits))
    (define maybe-p : Positive-Integer (bitwise-ior (bitwise-ior rbignum (arithmetic-shift head-byte (- nbits 8))) #b1))
    (cond [(prime? maybe-p) maybe-p] ; for big integers, `prime?` uses the probabilistic way.
          [else (random-odd-prime nbits block-bits)])))

(define random-nbits : (->* (Index) (Positive-Byte) Natural)
  (lambda [bits [block-bits 30]]
    (define block-size : Natural (arithmetic-shift 1 block-bits))
    (define max-blocks : Index (quotient bits block-bits))
    (define rem-bits : Byte (remainder bits block-bits))
    (let blockwise-random : Natural ([blocks : Nonnegative-Fixnum  0]
                                     [r : Natural (random (arithmetic-shift 1 rem-bits))])
      (cond [(>= blocks max-blocks) (bitwise-ior r (arithmetic-shift 1 (- bits 1)))]
            [else (blockwise-random (+ blocks 1)
                                    (bitwise-ior (arithmetic-shift r block-bits)
                                                 (random block-size)))]))))
