#lang typed/racket/base

(provide (all-defined-out))

(require racket/unsafe/ops)

;; Add two numbers in the GF(2^8) finite field
(define byte+ : (case-> [Byte Byte -> Byte]
                        [Byte Byte Byte -> Byte]
                        [Byte Byte Byte Byte -> Byte]
                        [Byte Byte Byte Byte Byte * -> Byte])
  (case-lambda
    [(n1 n2) (bitwise-xor n1 n2)]
    [(n1 n2 n3) (bitwise-xor n1 n2 n3)]
    [(n1 n2 n3 n4) (bitwise-xor n1 n2 n3 n4)]
    [(n1 n2 n3 n4 . ns) (apply bitwise-xor n1 n2 n3 ns)]))

;; Multiply two numbers in the GF(2^8) finite field defined by the polynomial x^8 + x^4 + x^3 + x + 1 = 0 (#b100011011)
(define byte* : (-> Byte Byte Byte)
  (lambda [factor1 factor2] ; TODO: learn timing attack
    (let russian-peasant ([product : Nonnegative-Fixnum 0]
                          [factor1 : Nonnegative-Fixnum factor1]
                          [factor2 : Nonnegative-Fixnum factor2]
                          [round : Index 0])
      (cond [(>= round 8) (unsafe-fxand product #xFF)]
            [else (let ([mask (if (bitwise-bit-set? factor1 7) #xFFFF 0)])
                    (russian-peasant (unsafe-fxxor product (unsafe-fxand (if (bitwise-bit-set? factor2 0) #xFFFF 0) factor1))
                                     (unsafe-fxxor (unsafe-fxlshift factor1 1) (unsafe-fxand mask #b100011011))
                                     (unsafe-fxrshift factor2 1)
                                     (+ round 1)))]))))
