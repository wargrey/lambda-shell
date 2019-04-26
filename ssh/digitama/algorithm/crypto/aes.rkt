#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

(provide (all-defined-out))

(require racket/unsafe/ops)

(require digimon/number)

(require "state.rkt")
(require "s-box.rkt")
(require "math.rkt")

(require (for-syntax racket/base))

(define aes-blocksize : 16 16)
(define aes-Nb : 4 4)

(define-syntax (aes-mix-columns! stx)
  (syntax-case stx []
    [(_ state c #:encrypt)
     #'(let ([s0c (state-array-ref state 0 c)]
             [s1c (state-array-ref state 1 c)]
             [s2c (state-array-ref state 2 c)]
             [s3c (state-array-ref state 3 c)])
         (state-array-set! state 0 c (byte+ (byte* #x02 s0c) (byte* #x03 s1c) s2c s3c))
         (state-array-set! state 1 c (byte+ s0c (byte* #x02 s1c) (byte* #x03 s2c) s3c))
         (state-array-set! state 2 c (byte+ s0c s1c (byte* #x02 s2c) (byte* #x03 s3c)))
         (state-array-set! state 3 c (byte+ (byte* #x03 s0c) s1c s2c (byte* #x02 s3c))))]
    [(_ state c #:decrypt)
     #'(let ([s0c (state-array-ref state 0 c)]
             [s1c (state-array-ref state 1 c)]
             [s2c (state-array-ref state 2 c)]
             [s3c (state-array-ref state 3 c)])
         (state-array-set! state 0 c (byte+ (byte* #x0e s0c) (byte* #x0b s1c) (byte* #x0d s2c) (byte* #x09 s3c)))
         (state-array-set! state 1 c (byte+ (byte* #x09 s0c) (byte* #x0e s1c) (byte* #x0b s2c) (byte* #x0d s3c)))
         (state-array-set! state 2 c (byte+ (byte* #x0d s0c) (byte* #x09 s1c) (byte* #x0e s2c) (byte* #x0b s3c)))
         (state-array-set! state 3 c (byte+ (byte* #x0b s0c) (byte* #x0d s1c) (byte* #x09 s2c) (byte* #x0e s3c))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; TODO: padding the plaintext if its length is not the multiple of the block size
(define aes-cipher : (-> Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [key]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 aes-Nb))
    (define key-schedule : (Vectorof Natural) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes]] : Bytes (aes-encrypt plaintext key-schedule state Nr))
            (λ [[ciphertext : Bytes]] : Bytes (aes-decrypt ciphertext key-schedule state Nr)))))

(define aes-cipher! : (-> Bytes
                          (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                  (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [key]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 aes-Nb))
    (define key-schedule : (Vectorof Natural) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart 0] [cend 0]] : Index
              (aes-encrypt! plaintext key-schedule state Nr pstart pend maybe-ciphertext cstart cend))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart 0] [pend 0]] : Index
              (aes-decrypt! ciphertext key-schedule state Nr cstart cend maybe-plaintext pstart pend)))))

(define aes-cipher-ctr : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 aes-Nb))
    (define key-schedule : (Vectorof Natural) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes]] : Bytes (aes-encrypt plaintext key-schedule state Nr 0 0 IV))
            (λ [[ciphertext : Bytes]] : Bytes (aes-decrypt ciphertext key-schedule state Nr 0 0 IV)))))

(define aes-cipher-ctr! : (-> Bytes Bytes
                              (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                      (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [IV key]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 aes-Nb))
    (define key-schedule : (Vectorof Natural) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart : Natural 0] [cend : Natural 0]] : Index
              (aes-encrypt! plaintext key-schedule state Nr pstart pend maybe-ciphertext cstart cend IV))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart : Natural 0] [pend : Natural 0]] : Index
              (aes-decrypt! ciphertext key-schedule state Nr cstart cend maybe-plaintext pstart pend IV)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-encrypt : (->* (Bytes (Vectorof Natural) State-Array Byte) (Natural Natural Bytes) Bytes)
  (lambda [plaintext schedule state round [pstart 0] [pend0 0] [counter #""]]
    (define pend : Index (bytes-range-end plaintext pstart pend0))
    (define ciphertext : Bytes (make-bytes (aes-ciphertext-size (- pend pstart))))

    (aes-encrypt! plaintext schedule state round pstart pend ciphertext 0 0 counter)
    ciphertext))

(define aes-encrypt! : (->* (Bytes (Vectorof Natural) State-Array Byte) (Natural Natural (Option Bytes) Natural Natural Bytes) Index)
  (lambda [plaintext schedule state round [pstart 0] [pend0 0] [maybe-ciphertext #false] [cstart0 0] [cend0 0] [counter #""]]
    (define pend : Index (bytes-range-end plaintext pstart pend0))
    (define-values (ciphertext cstart cend)
      (cond [(not maybe-ciphertext) (values plaintext pstart pend)]
            [else (values maybe-ciphertext cstart0 (bytes-range-end maybe-ciphertext cstart0 cend0))]))

    (displayln (list (cons pstart pend) (cons cstart cend)))
    (if (= (bytes-length counter) aes-blocksize)
        (let encrypt-block ([pidx : Nonnegative-Fixnum (assert pstart index?)]
                            [cidx : Nonnegative-Fixnum (assert cstart index?)])
          (when (and (< pidx pend) (< cidx cend))
            (aes-block-encrypt plaintext pidx pend ciphertext cidx cend schedule state round)
            (aes-block-ctr-xor ciphertext cidx cend counter)
            (network-natural-bytes++ counter)
            (encrypt-block (+ pidx aes-blocksize) (+ cidx aes-blocksize))))
        (let encrypt-block ([pidx : Nonnegative-Fixnum (assert pstart index?)]
                            [cidx : Nonnegative-Fixnum (assert cstart index?)])
          (when (and (< pidx pend) (< cidx cend))
            (aes-block-encrypt plaintext pidx pend ciphertext cidx cend schedule state round)
            (encrypt-block (+ pidx aes-blocksize) (+ cidx aes-blocksize)))))

    cend))

(define aes-decrypt : (->* (Bytes (Vectorof Natural) State-Array Byte) (Natural Natural Bytes) Bytes)
  (lambda [ciphertext schedule state round [cstart 0] [cend0 0] [counter #""]]
    (define cend : Index (bytes-range-end ciphertext cstart cend0))
    (define plaintext : Bytes (make-bytes (- cend cstart)))

    (aes-decrypt! ciphertext schedule state round cstart cend plaintext 0 0 counter)
    plaintext))

(define aes-decrypt! : (->* (Bytes (Vectorof Natural) State-Array Byte) (Natural Natural (Option Bytes) Natural Natural Bytes) Index)
  (lambda [ciphertext schedule state round [cstart 0] [cend0 0] [maybe-plaintext #false] [pstart0 0] [pend0 0] [counter #""]]
    (define cend : Index (bytes-range-end ciphertext cstart cend0))
    (define-values (plaintext pstart pend)
      (cond [(not maybe-plaintext) (values ciphertext cstart cend)]
            [else (values maybe-plaintext pstart0 (bytes-range-end maybe-plaintext pstart0 pend0))]))

    (if (= (bytes-length counter) aes-blocksize)
        (let encrypt-block ([cidx : Nonnegative-Fixnum (assert cstart index?)]
                            [pidx : Nonnegative-Fixnum (assert pstart index?)])
          (when (and (< cidx cend) (< pidx pend))
            (aes-block-decrypt ciphertext cidx cend plaintext pidx pend schedule state round)
            (aes-block-ctr-xor plaintext pidx pend counter)
            (network-natural-bytes++ counter)
            (encrypt-block (+ cidx aes-blocksize) (+ pidx aes-blocksize))))
        (let encrypt-block ([cidx : Nonnegative-Fixnum (assert cstart index?)]
                            [pidx : Nonnegative-Fixnum (assert pstart index?)])
          (when (and (< cidx cend) (< pidx pend))
            (aes-block-decrypt ciphertext cidx cend plaintext pidx pend schedule state round)
            (encrypt-block (+ cidx aes-blocksize) (+ pidx aes-blocksize)))))

    pend))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-block-encrypt : (-> Bytes Index Index Bytes Index Index (Vectorof Natural) State-Array Byte Void)
  (lambda [plainblock pstart pend cipherblock cstart cend schedule state round]
    (define last-round-idx : Index (* aes-Nb round))
    
    (state-array-copy-from-bytes! state plainblock pstart pend)
    (state-array-add-round-key! state schedule 0)

    (let encrypt ([widx : Nonnegative-Fixnum aes-Nb])
      (when (< widx last-round-idx)
        (state-array-substitute! state aes-substitute-box)
        (aes-left-shift-rows! state)

        (aes-mix-columns! state 0 #:encrypt)
        (aes-mix-columns! state 1 #:encrypt)
        (aes-mix-columns! state 2 #:encrypt)
        (aes-mix-columns! state 3 #:encrypt)
        
        (state-array-add-round-key! state schedule widx)
        
        (encrypt (+ widx aes-Nb))))

    (state-array-substitute! state aes-substitute-box)
    (aes-left-shift-rows! state)
    (state-array-add-round-key! state schedule last-round-idx)
    
    (state-array-copy-to-bytes! state cipherblock cstart cend)))

(define aes-block-decrypt : (-> Bytes Index Index Bytes Index Index (Vectorof Natural) State-Array Byte Void)
  (lambda [cipherblock cstart cend plaintext pstart pend schedule state round]
    (define last-round-idx : Index (* aes-Nb round))
    
    (state-array-copy-from-bytes! state cipherblock cstart cend)
    (state-array-add-round-key! state schedule last-round-idx)

    (let encrypt ([widx : Fixnum (- last-round-idx aes-Nb)])
      (when (> widx 0)
        (state-array-substitute! state aes-inverse-substitute-box)
        (aes-right-shift-rows! state)
        (state-array-add-round-key! state schedule widx)

        (aes-mix-columns! state 0 #:decrypt)
        (aes-mix-columns! state 1 #:decrypt)
        (aes-mix-columns! state 2 #:decrypt)
        (aes-mix-columns! state 3 #:decrypt)
        
        (encrypt (- widx aes-Nb))))

    (state-array-substitute! state aes-inverse-substitute-box)
    (aes-right-shift-rows! state)
    (state-array-add-round-key! state schedule 0)
    
    (state-array-copy-to-bytes! state plaintext pstart pend)))

(define aes-block-ctr-xor : (-> Bytes Index Positive-Index Bytes Void)
  (lambda [block start end counter]
    (define xor-step : 8 8)
    (let ctr-xor ([bidx : Nonnegative-Fixnum start]
                  [cidx : Index 0])
      (when (and (< bidx end) (< cidx aes-blocksize))
        (define bnext : Nonnegative-Fixnum (+ bidx xor-step))
        (define cnext : Index (+ cidx xor-step))
        (define ctr : Integer
          (bitwise-xor (integer-bytes->integer block #false #true bidx bnext)
                       (integer-bytes->integer counter #false #true cidx cnext)))

        (integer->integer-bytes ctr xor-step #false #true block bidx)
        (ctr-xor bnext cnext)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-key-expand : (-> Bytes (Vectorof Natural))
  (lambda [key]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define size : Index (assert (unsafe-fx* aes-Nb (+ Nr 1)) index?))
    (define schedule : (Vectorof Natural) (make-vector size))

    (let copy ([widx : Index 0])
      (when (< widx Nk)
        (define key-idx : Index (* widx 4))
        (vector-set! schedule widx (integer-bytes->integer key #false #true key-idx (+ key-idx 4)))
        (copy (+ widx 1))))
    
    (let expand ([widx : Nonnegative-Fixnum Nk])
      (when (< widx size)
        (define-values (i/Nk i%Nk) (quotient/remainder widx Nk))
        (define temp : Natural
          (let ([temp (vector-ref schedule (- widx 1))])
            (cond [(= i%Nk 0) (aes-substitute+rotate-word temp aes-substitute-box (aes-rcon i/Nk))]
                  [(and (> Nk 6) (= i%Nk 4)) (aes-substitute-word temp aes-substitute-box)]
                  [else temp])))
        
        (vector-set! schedule widx (bitwise-xor (vector-ref schedule (- widx Nk)) temp))
        
        (expand (+ widx 1))))
    
    schedule))

(define aes-key-schedule-rotate! : (-> (Vectorof Natural) Void)
  (lambda [schedule]
    (define idxmax : Index (vector-length schedule))

    (let rotate ([idx : Nonnegative-Fixnum 0])
      (when (< idx idxmax)
        (define w1 : Natural (vector-ref schedule (+ idx 0)))
        (define w2 : Natural (vector-ref schedule (+ idx 1)))
        (define w3 : Natural (vector-ref schedule (+ idx 2)))
        (define w4 : Natural (vector-ref schedule (+ idx 3)))

        (vector-set! schedule (+ idx 0)
                     (bitwise-ior (arithmetic-shift (bitwise-and (arithmetic-shift w1 -24) #xFF) 24)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w2 -24) #xFF) 16)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w3 -24) #xFF) 08)
                                  (unsafe-fxand (arithmetic-shift w4 -24) #xFF)))

        (vector-set! schedule (+ idx 1)
                     (bitwise-ior (arithmetic-shift (bitwise-and (arithmetic-shift w1 -16) #xFF) 24)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w2 -16) #xFF) 16)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w3 -16) #xFF) 08)
                                  (unsafe-fxand (arithmetic-shift w4 -16) #xFF)))

        (vector-set! schedule (+ idx 2)
                     (bitwise-ior (arithmetic-shift (bitwise-and (arithmetic-shift w1 -08) #xFF) 24)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w2 -08) #xFF) 16)
                                  (unsafe-fxlshift (unsafe-fxand (arithmetic-shift w3 -08) #xFF) 08)
                                  (unsafe-fxand (arithmetic-shift w4 -08) #xFF)))
        
        (vector-set! schedule (+ idx 3)
                     (bitwise-ior (arithmetic-shift (bitwise-and w1 #xFF) 24)
                                  (unsafe-fxlshift (unsafe-fxand w2 #xFF) 16)
                                  (unsafe-fxlshift (unsafe-fxand w3 #xFF) 08)
                                  (unsafe-fxand w4 #xFF)))
        
        (rotate (+ idx 4))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-words-size : (-> Bytes Byte)
  (lambda [src]
    (assert (quotient (bytes-length src) 4) byte?)))

(define aes-round : (-> Byte Byte)
  (lambda [Nk]
    (assert (+ Nk 6) byte?)))

(define aes-left-shift-rows! : (-> State-Array Void)
  (lambda [state]
    (state-array-left-shift-word! state 1 0 08)
    (state-array-left-shift-word! state 2 0 16)
    (state-array-left-shift-word! state 3 0 24)))

(define aes-right-shift-rows! : (-> State-Array Void)
  (lambda [state]
    (state-array-right-shift-word! state 1 0 08)
    (state-array-right-shift-word! state 2 0 16)
    (state-array-right-shift-word! state 3 0 24)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-substitute+rotate-word : (-> Natural Bytes Byte Natural)
  (lambda [temp s-box rc]
    (define w0 : Byte (unsafe-fxand (arithmetic-shift temp -24) #xFF))
    (define w1 : Byte (unsafe-fxand (arithmetic-shift temp -16) #xFF))
    (define w2 : Byte (unsafe-fxand (arithmetic-shift temp -08) #xFF))
    (define w3 : Byte (unsafe-fxand temp #xFF))

    (bitwise-ior (arithmetic-shift (bitwise-xor (unsafe-bytes-ref s-box w1) rc) 24)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w2) 16)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w3) 08)
                 (unsafe-bytes-ref s-box w0))))

(define aes-substitute-word : (-> Natural Bytes Natural)
  (lambda [temp s-box]
    (define w0 : Byte (unsafe-fxand (arithmetic-shift temp -24) #xFF))
    (define w1 : Byte (unsafe-fxand (arithmetic-shift temp -16) #xFF))
    (define w2 : Byte (unsafe-fxand (arithmetic-shift temp -08) #xFF))
    (define w3 : Byte (unsafe-fxand temp #xFF))

    (bitwise-ior (arithmetic-shift (unsafe-bytes-ref s-box w0) 24)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w1) 16)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w2) 08)
                 (unsafe-bytes-ref s-box w3))))

(define aes-rcon : (-> Index Byte)
  ;; https://en.wikipedia.org/wiki/Rijndael_key_schedule
  (let* ([prefab-rcs : (Vectorof Byte) (vector #x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36)]
         [prefab-size : Index (vector-length prefab-rcs)])
    (lambda [i]
      (cond [(<= i prefab-size) (vector-ref prefab-rcs (- i 1))]
            [else (let 2rci-1 ([it : Nonnegative-Fixnum (max (- prefab-size 1) 0)]
                               [rc : Nonnegative-Fixnum (vector-ref prefab-rcs (- prefab-size 1))])
                    (cond [(>= it i) (bitwise-and rc #xFF)]
                          [else (2rci-1 (+ it 1)
                                        (bitwise-xor (unsafe-fxlshift rc 1)
                                                     (if (< rc #x80) #x00 #x11B)))]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-ciphertext-size : (-> Integer Natural)
  (lambda [plaintext-size]
    (define size : Natural (max plaintext-size 0))

    (* (inexact->exact (ceiling (/ size aes-blocksize))) aes-blocksize)))
