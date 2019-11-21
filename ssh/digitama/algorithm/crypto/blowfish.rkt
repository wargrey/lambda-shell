#lang typed/racket/base

(provide (all-defined-out))
(provide (rename-out [bf-blocksize blowfish-blocksize]))

(require racket/unsafe/ops)

(require digimon/number)

(require "blowfish/s-box.rkt")
(require "blowfish/encryption.rkt")

(require "utility.rkt")

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

(define blowfish-cipher-cbc : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (define-values (parray sbox) (blowfish-make-boxes key))

    (values (λ [[plaintext : Bytes]] : Bytes (blowfish-encrypt-cbc IV plaintext parray sbox))
            (λ [[ciphertext : Bytes]] : Bytes (blowfish-decrypt-cbc IV ciphertext parray sbox)))))

(define blowfish-cipher-cbc! : (-> Bytes Bytes
                                   (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                           (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [IV key]
    (define-values (parray sbox) (blowfish-make-boxes key))

    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart 0] [cend 0]] : Index
              (blowfish-encrypt-cbc! IV plaintext parray sbox pstart pend maybe-ciphertext cstart cend))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart 0] [pend 0]] : Index
              (blowfish-decrypt-cbc! IV ciphertext parray sbox cstart cend maybe-plaintext pstart pend)))))

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
          (encrypt-block (blowfish-block-encrypt plaintext pidx ciphertext cidx parray sbox)
                         (unsafe-fx+ cidx bf-blocksize))))
      
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
          (encrypt-block (blowfish-block-decrypt ciphertext cidx plaintext pidx parray sbox)
                         (unsafe-fx+ pidx bf-blocksize))))
      
      pend)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define blowfish-encrypt-cbc : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural) Bytes)
  (lambda [IV plaintext parray sbox [pstart 0] [pend0 0]]
    (define pend : Index (bytes-range-end plaintext pstart pend0))
    (define ciphertext : Bytes (make-bytes (ciphertext-size (- pend pstart) bf-blocksize)))

    (blowfish-encrypt-cbc! IV plaintext parray sbox pstart pend ciphertext)
    ciphertext))

(define blowfish-encrypt-cbc! : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [IV plaintext parray sbox [pstart 0] [pend0 0] [maybe-ciphertext #false] [cstart0 0] [cend0 0]]
    (with-asserts ([pstart  fixnum?]
                   [cstart0 fixnum?])
      (define pend : Index (bytes-range-end plaintext pstart pend0))
      (define-values (ciphertext cstart cend)
        (cond [(not maybe-ciphertext) (values plaintext pstart pend)]
              [else (values maybe-ciphertext cstart0 (bytes-range-end maybe-ciphertext cstart0 cend0))]))

      (let encrypt-block ([pidx : Nonnegative-Fixnum pstart]
                          [cidx : Nonnegative-Fixnum cstart]
                          [cbcL : Natural (integer-bytes->integer IV #false #true 0 4)]
                          [cbcR : Natural (integer-bytes->integer IV #false #true 4 8)])
        (when (< pidx pend)
          (define-values (pidx++ L R) (blowfish-block-encrypt plaintext pidx ciphertext cidx parray sbox cbcL cbcR))
          (encrypt-block pidx++ (unsafe-fx+ cidx bf-blocksize) L R)))
      
      cend)))

(define blowfish-decrypt-cbc : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural) Bytes)
  (lambda [IV ciphertext parray sbox [cstart 0] [cend0 0]]
    (define cend : Index (bytes-range-end ciphertext cstart cend0))
    (define plaintext : Bytes (make-bytes (- cend cstart)))

    (blowfish-decrypt-cbc! IV ciphertext parray sbox cstart cend plaintext)
    plaintext))

(define blowfish-decrypt-cbc! : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (Vectorof Natural)) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [IV ciphertext parray sbox [cstart 0] [cend0 0] [maybe-plaintext #false] [pstart0 0] [pend0 0]]
    (with-asserts ([cstart  fixnum?]
                   [pstart0 fixnum?])
      (define cend : Index (bytes-range-end ciphertext cstart cend0))
      (define-values (plaintext pstart pend)
        (cond [(not maybe-plaintext) (values ciphertext cstart cend)]
              [else (values maybe-plaintext pstart0 (bytes-range-end maybe-plaintext pstart0 pend0))]))
      
      (let decrypt-block ([cidx : Nonnegative-Fixnum cstart]
                          [pidx : Nonnegative-Fixnum pstart]
                          [cbcL : Natural (integer-bytes->integer IV #false #true 0 4)]
                          [cbcR : Natural (integer-bytes->integer IV #false #true 4 8)])
        (when (< cidx cend)
          (define-values (cidx++ L R) (blowfish-block-decrypt ciphertext cidx plaintext pidx parray sbox cbcL cbcR))
          (decrypt-block cidx++ (unsafe-fx+ pidx bf-blocksize) L R)))
      
      pend)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define blowfish-block-encrypt : (case-> [Bytes Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural) -> Nonnegative-Fixnum]
                                         [Bytes Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural)
                                                Natural Natural -> (Values Nonnegative-Fixnum Natural Natural)])
  (case-lambda
    [(plainblock pstart cipherblock cstart parray sbox)
     (define-values (pridx pend cridx) (values (+ pstart 4) (+ pstart bf-blocksize) (+ cstart 4)))
     (define pL : Natural (integer-bytes->integer plainblock #false #true pstart pridx))
     (define pR : Natural (integer-bytes->integer plainblock #false #true pridx pend))
     (define-values (cL cR) (bf-encrypt pL pR parray sbox))
     
     (integer->integer-bytes cL 4 #false #true cipherblock cstart)
     (integer->integer-bytes cR 4 #false #true cipherblock cridx)
     
     pend]
    [(plainblock pstart cipherblock cstart parray sbox cbcL cbcR)
     (define-values (pridx pend cridx) (values (+ pstart 4) (+ pstart bf-blocksize) (+ cstart 4)))
     (define pL : Natural (integer-bytes->integer plainblock #false #true pstart pridx))
     (define pR : Natural (integer-bytes->integer plainblock #false #true pridx pend))
     (define-values (cL cR) (bf-encrypt (unsafe-fxxor pL cbcL) (unsafe-fxxor pR cbcR) parray sbox))
     
     (integer->integer-bytes cL 4 #false #true cipherblock cstart)
     (integer->integer-bytes cR 4 #false #true cipherblock cridx)
     
     (values pend cL cR)]))

(define blowfish-block-decrypt : (case-> [Bytes Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural) -> Nonnegative-Fixnum]
                                         [Bytes Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (Vectorof Natural)
                                                Natural Natural -> (Values Nonnegative-Fixnum Natural Natural)])
  (case-lambda
    [(cipherblock cstart plainblock pstart parray sbox)
     (define-values (pridx cridx cend) (values (+ pstart 4) (+ cstart 4) (+ cstart bf-blocksize)))
     (define cL : Natural (integer-bytes->integer cipherblock #false #true cstart cridx))
     (define cR : Natural (integer-bytes->integer cipherblock #false #true cridx cend))
     (define-values (pL pR) (bf-decrypt cL cR parray sbox))
     
     (integer->integer-bytes pL 4 #false #true plainblock pstart)
     (integer->integer-bytes pR 4 #false #true plainblock pridx)
     
     cend]
    [(cipherblock cstart plainblock pstart parray sbox cbcL cbcR)
     (define-values (pridx cridx cend) (values (+ pstart 4) (+ cstart 4) (+ cstart bf-blocksize)))
     (define cL : Natural (integer-bytes->integer cipherblock #false #true cstart cridx))
     (define cR : Natural (integer-bytes->integer cipherblock #false #true cridx cend))
     (define-values (pL pR) (bf-decrypt cL cR parray sbox))
     
     (integer->integer-bytes (unsafe-fxxor pL cbcL) 4 #false #true plainblock pstart)
     (integer->integer-bytes (unsafe-fxxor pR cbcR) 4 #false #true plainblock pridx)
     
     (values cend cL cR)]))
