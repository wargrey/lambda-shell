#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

(provide (all-defined-out))

(require racket/unsafe/ops)

(require digimon/number)

(require "blowfish/s-box.rkt")
(require "blowfish/encryption.rkt")
(require "utility.rkt")

(require (for-syntax racket/base))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; TODO: padding the plaintext if its length is not the multiple of the block size
(define blowfish-cipher : (-> Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [key]
    (define-values (parray sbox) (blowfish-make-boxes key))

    (values (λ [[plaintext : Bytes]] : Bytes (blowfish-encrypt plaintext parray sbox))
            (λ [[ciphertext : Bytes]] : Bytes (blowfish-decrypt ciphertext parray sbox)))))

(define blowfish-cipher! : (-> Bytes
                               (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                       (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [key]
    (define-values (parray sbox) (blowfish-make-boxes key))

    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart 0] [cend 0]] : Index
              (blowfish-encrypt! plaintext parray sbox pstart pend maybe-ciphertext cstart cend))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart 0] [pend 0]] : Index
              (blowfish-decrypt! ciphertext parray sbox cstart cend maybe-plaintext pstart pend)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define blowfish-encrypt : (->* (Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural) Bytes)
  (lambda [plaintext parray sbox [pstart 0] [pend0 0]]
    (define pend : Index (bytes-range-end plaintext pstart pend0))
    (define ciphertext : Bytes (make-bytes (ciphertext-size (- pend pstart) bf-blocksize)))

    (blowfish-encrypt! plaintext parray sbox pstart pend ciphertext)
    ciphertext))

(define blowfish-encrypt! : (->* (Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [plaintext parray sbox [pstart 0] [pend0 0] [maybe-ciphertext #false] [cstart0 0] [cend0 0]]
    (with-asserts ([pstart  fixnum?]
                   [cstart0 fixnum?])
      (define pend : Index (bytes-range-end plaintext pstart pend0))
      (define-values (ciphertext cstart cend)
        (cond [(not maybe-ciphertext) (values plaintext pstart pend)]
              [else (values maybe-ciphertext cstart0 (bytes-range-end maybe-ciphertext cstart0 cend0))]))
      
      (let encrypt-block ([pidx : Nonnegative-Fixnum pstart]
                          [cidx : Nonnegative-Fixnum cstart])
        (when (< pidx pend)
          (blowfish-block-encrypt plaintext pidx pend ciphertext cidx parray sbox)
          (encrypt-block (+ pidx bf-blocksize) (unsafe-fx+ cidx bf-blocksize))))
      
      cend)))

(define blowfish-decrypt : (->* (Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural) Bytes)
  (lambda [ciphertext parray sbox [cstart 0] [cend0 0]]
    (define cend : Index (bytes-range-end ciphertext cstart cend0))
    (define plaintext : Bytes (make-bytes (- cend cstart)))

    (blowfish-decrypt! ciphertext parray sbox cstart cend plaintext)
    plaintext))

(define blowfish-decrypt! : (->* (Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [ciphertext parray sbox [cstart 0] [cend0 0] [maybe-plaintext #false] [pstart0 0] [pend0 0]]
    (with-asserts ([cstart  fixnum?]
                   [pstart0 fixnum?])
      (define cend : Index (bytes-range-end ciphertext cstart cend0))
      (define-values (plaintext pstart pend)
        (cond [(not maybe-plaintext) (values ciphertext cstart cend)]
              [else (values maybe-plaintext pstart0 (bytes-range-end maybe-plaintext pstart0 pend0))]))
      
      (let encrypt-block ([cidx : Nonnegative-Fixnum cstart]
                          [pidx : Nonnegative-Fixnum pstart])
        (when (< cidx cend)
          (blowfish-block-decrypt ciphertext cidx cend plaintext pidx parray sbox)
          (encrypt-block (+ cidx bf-blocksize) (unsafe-fx+ pidx bf-blocksize))))
      
      pend)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define blowfish-block-encrypt : (-> Bytes Index Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural) Void)
  (lambda [plainblock pstart pend cipherblock cstart parray sbox]
    (define-values (pridx cridx) (values (+ pstart 4) (+ cstart 4)))
    (define pL : Natural (integer-bytes->integer plainblock #false #true pstart pridx))
    (define pR : Natural (integer-bytes->integer plainblock #false #true pridx pend))
    (define-values (cL cR) (bf-encrypt pL pR parray sbox))

    (integer->integer-bytes cL 4 #false #true cipherblock cstart)
    (integer->integer-bytes cR 4 #false #true cipherblock cridx)

    (void)))

(define blowfish-block-decrypt : (-> Bytes Index Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural) Void)
  (lambda [cipherblock cstart cend plainblock pstart parray sbox]
    (define-values (pridx cridx) (values (+ pstart 4) (+ cstart 4)))
    (define cL : Natural (integer-bytes->integer cipherblock #false #true cstart cridx))
    (define cR : Natural (integer-bytes->integer cipherblock #false #true cridx cend))
    (define-values (pL pR) (bf-decrypt cL cR parray sbox))

    (integer->integer-bytes pL 4 #false #true plainblock pstart)
    (integer->integer-bytes pR 4 #false #true plainblock pridx)

    (void)))
