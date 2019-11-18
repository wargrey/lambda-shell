#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

(provide (all-defined-out))

(require racket/unsafe/ops)

(require digimon/number)

(require "aes/state.rkt")
(require "aes/s-box.rkt")
(require "math.rkt")

(require (for-syntax racket/base))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-state-array aes 4 4)

(define-syntax (aes-mix-columns! stx)
  (syntax-case stx []
    [(_ state c #:encrypt)
     #'(let ([s0c (aes-state-array-ref state 0 c)]
             [s1c (aes-state-array-ref state 1 c)]
             [s2c (aes-state-array-ref state 2 c)]
             [s3c (aes-state-array-ref state 3 c)])
         (aes-state-array-set! state 0 c (byte+ (byte* #x02 s0c) (byte* #x03 s1c) s2c s3c))
         (aes-state-array-set! state 1 c (byte+ s0c (byte* #x02 s1c) (byte* #x03 s2c) s3c))
         (aes-state-array-set! state 2 c (byte+ s0c s1c (byte* #x02 s2c) (byte* #x03 s3c)))
         (aes-state-array-set! state 3 c (byte+ (byte* #x03 s0c) s1c s2c (byte* #x02 s3c))))]
    [(_ state c #:decrypt)
     #'(let ([s0c (aes-state-array-ref state 0 c)]
             [s1c (aes-state-array-ref state 1 c)]
             [s2c (aes-state-array-ref state 2 c)]
             [s3c (aes-state-array-ref state 3 c)])
         (aes-state-array-set! state 0 c (byte+ (byte* #x0e s0c) (byte* #x0b s1c) (byte* #x0d s2c) (byte* #x09 s3c)))
         (aes-state-array-set! state 1 c (byte+ (byte* #x09 s0c) (byte* #x0e s1c) (byte* #x0b s2c) (byte* #x0d s3c)))
         (aes-state-array-set! state 2 c (byte+ (byte* #x0d s0c) (byte* #x09 s1c) (byte* #x0e s2c) (byte* #x0b s3c)))
         (aes-state-array-set! state 3 c (byte+ (byte* #x0b s0c) (byte* #x0d s1c) (byte* #x09 s2c) (byte* #x0e s3c))))]))

(define-syntax (aes-step stx)
  (syntax-case stx []
    [(_ state aes-substitute-box schedule widx #:encrypt)
     #'(begin (aes-state-array-substitute! state aes-substitute-box)
              (aes-left-shift-rows! state)

              (aes-mix-columns! state 0 #:encrypt)
              (aes-mix-columns! state 1 #:encrypt)
              (aes-mix-columns! state 2 #:encrypt)
              (aes-mix-columns! state 3 #:encrypt)
        
              (aes-state-array-add-round-key! state schedule widx))]
    [(_ state aes-inverse-substitute-box schedule widx #:decrypt)
     #'(begin (aes-state-array-substitute! state aes-inverse-substitute-box)
              (aes-right-shift-rows! state)
              (aes-state-array-add-round-key! state schedule widx)
              
              (aes-mix-columns! state 0 #:decrypt)
              (aes-mix-columns! state 1 #:decrypt)
              (aes-mix-columns! state 2 #:decrypt)
              (aes-mix-columns! state 3 #:decrypt))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; TODO: padding the plaintext if its length is not the multiple of the block size
(define aes-cipher : (-> Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [key]
    (define Nr-lidx : Index (aes-last-round-idx key))
    (define state : (State-Array 4 4) (make-aes-state-array))
    (define key-schedule : (Vectorof Nonnegative-Fixnum) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes]] : Bytes (aes-encrypt plaintext key-schedule state Nr-lidx))
            (λ [[ciphertext : Bytes]] : Bytes (aes-decrypt ciphertext key-schedule state Nr-lidx)))))

(define aes-cipher! : (-> Bytes
                          (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                  (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [key]
    (define Nr : Index (aes-last-round-idx key))
    (define state : (State-Array 4 4) (make-aes-state-array))
    (define key-schedule : (Vectorof Nonnegative-Fixnum) (aes-key-expand key))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart 0] [cend 0]] : Index
              (aes-encrypt! plaintext key-schedule state Nr pstart pend maybe-ciphertext cstart cend))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart 0] [pend 0]] : Index
              (aes-decrypt! ciphertext key-schedule state Nr cstart cend maybe-plaintext pstart pend)))))

(define aes-cipher-ctr : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (define Nr-lidx : Index (aes-last-round-idx key))
    (define state : (State-Array 4 4) (make-aes-state-array))
    (define key-schedule : (Vectorof Nonnegative-Fixnum) (aes-key-expand key))
    (define encrypt-ctr : Bytes (bytes-copy IV))
    (define decrypt-ctr : Bytes (bytes-copy IV))
    (define AES-K-IV : Bytes (make-bytes aes-blocksize))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes]] : Bytes (aes-crypt-ctr plaintext encrypt-ctr key-schedule state Nr-lidx 0 0 AES-K-IV))
            (λ [[ciphertext : Bytes]] : Bytes (aes-crypt-ctr ciphertext decrypt-ctr key-schedule state Nr-lidx 0 0 AES-K-IV)))))

(define aes-cipher-ctr! : (-> Bytes Bytes
                              (Values (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)
                                      (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index)))
  (lambda [IV key]
    (define Nr-lidx : Index (aes-last-round-idx key))
    (define state : (State-Array 4 4) (make-aes-state-array))
    (define key-schedule : (Vectorof Nonnegative-Fixnum) (aes-key-expand key))
    (define encrypt-ctr : Bytes (bytes-copy IV))
    (define decrypt-ctr : Bytes (bytes-copy IV))
    (define AES-K-IV : Bytes (make-bytes aes-blocksize))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes] [pstart : Natural 0] [pend : Natural 0] [maybe-ciphertext #false] [cstart : Natural 0] [cend : Natural 0]] : Index
              (aes-crypt-ctr! plaintext encrypt-ctr key-schedule state Nr-lidx pstart pend maybe-ciphertext cstart cend AES-K-IV))
            (λ [[ciphertext : Bytes] [cstart : Natural 0] [cend : Natural 0] [maybe-plaintext #false] [pstart : Natural 0] [pend : Natural 0]] : Index
              (aes-crypt-ctr! ciphertext decrypt-ctr key-schedule state Nr-lidx cstart cend maybe-plaintext pstart pend AES-K-IV)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-encrypt : (->* (Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural) Bytes)
  (lambda [plaintext schedule state Nr-lidx [pstart 0] [pend0 0]]
    (define pend : Index (bytes-range-end plaintext pstart pend0))
    (define ciphertext : Bytes (make-bytes (aes-ciphertext-size (- pend pstart))))

    (aes-encrypt! plaintext schedule state Nr-lidx pstart pend ciphertext)
    ciphertext))

(define aes-encrypt! : (->* (Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [plaintext schedule state Nr-lidx [pstart 0] [pend0 0] [maybe-ciphertext #false] [cstart0 0] [cend0 0]]
    (with-asserts ([pstart  fixnum?]
                   [cstart0 fixnum?])
      (define pend : Index (bytes-range-end plaintext pstart pend0))
      (define-values (ciphertext cstart cend)
        (cond [(not maybe-ciphertext) (values plaintext pstart pend)]
              [else (values maybe-ciphertext cstart0 (bytes-range-end maybe-ciphertext cstart0 cend0))]))
      
      (let encrypt-block ([pidx : Nonnegative-Fixnum pstart]
                          [cidx : Nonnegative-Fixnum cstart])
        (when (< pidx pend)
          (aes-block-encrypt plaintext pidx pend ciphertext cidx schedule state Nr-lidx)
          (encrypt-block (+ pidx aes-blocksize) (unsafe-fx+ cidx aes-blocksize))))
      
      cend)))

(define aes-decrypt : (->* (Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural) Bytes)
  (lambda [ciphertext schedule state Nr-lidx [cstart 0] [cend0 0]]
    (define cend : Index (bytes-range-end ciphertext cstart cend0))
    (define plaintext : Bytes (make-bytes (- cend cstart)))

    (aes-decrypt! ciphertext schedule state Nr-lidx cstart cend plaintext)
    plaintext))

(define aes-decrypt! : (->* (Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural (Option Bytes) Natural Natural) Index)
  (lambda [ciphertext schedule state Nr-lidx [cstart 0] [cend0 0] [maybe-plaintext #false] [pstart0 0] [pend0 0]]
    (with-asserts ([cstart  fixnum?]
                   [pstart0 fixnum?])
      (define cend : Index (bytes-range-end ciphertext cstart cend0))
      (define-values (plaintext pstart pend)
        (cond [(not maybe-plaintext) (values ciphertext cstart cend)]
              [else (values maybe-plaintext pstart0 (bytes-range-end maybe-plaintext pstart0 pend0))]))
      
      (let encrypt-block ([cidx : Nonnegative-Fixnum cstart]
                          [pidx : Nonnegative-Fixnum pstart])
        (when (< cidx cend)
          (aes-block-decrypt ciphertext cidx cend plaintext pidx schedule state Nr-lidx)
          (encrypt-block (+ cidx aes-blocksize) (unsafe-fx+ pidx aes-blocksize))))
      
      pend)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NOTE: CTR does not require a decryption algorithm
(define aes-crypt-ctr : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural Bytes) Bytes)
  (lambda [text counter schedule state Nr-lidx [tstart 0] [tend0 0] [aes-k-iv (make-bytes aes-blocksize)]]
    (define tend : Index (bytes-range-end text tstart tend0))
    (define result : Bytes (make-bytes (aes-ciphertext-size (- tend tstart))))

    (aes-crypt-ctr! text counter schedule state Nr-lidx tstart tend result 0 0 aes-k-iv)
    result))

(define aes-crypt-ctr! : (->* (Bytes Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index) (Natural Natural (Option Bytes) Natural Natural Bytes) Index)
  (lambda [intext counter schedule state Nr-lidx [istart 0] [iend0 0] [maybe-outtext #false] [ostart0 0] [oend0 0] [aes-k-iv (make-bytes aes-blocksize)]]
    (define iend : Index (bytes-range-end intext istart iend0))

    ;; NOTE: this optimization does not make sense
    (cond [(not maybe-outtext) (aes-block-ctr intext counter schedule state Nr-lidx istart iend aes-k-iv) iend]
          [else (let ([oend (bytes-range-end maybe-outtext ostart0 oend0)])
                  (aes-block-ctr intext counter schedule state Nr-lidx istart iend maybe-outtext ostart0 aes-k-iv)
                  oend)])))

(define aes-block-ctr : (case-> [Bytes Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index Natural Index Bytes Natural Bytes -> Void]
                                [Bytes Bytes (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index Natural Index Bytes -> Void])
  (case-lambda
    [(intext counter schedule state Nr-lidx istart iend outtext ostart aes-k-iv)
     (let crypt-block ([iidx : Nonnegative-Fixnum (assert istart fixnum?)]
                       [oidx : Nonnegative-Fixnum (assert ostart fixnum?)])
       (when (< iidx iend)
         (aes-block-encrypt counter 0 aes-blocksize aes-k-iv 0 schedule state Nr-lidx)
         (aes-ctr-block-xor! intext iidx outtext oidx aes-k-iv)
         (network-natural-bytes++ counter)
         (crypt-block (+ iidx aes-blocksize) (unsafe-fx+ oidx aes-blocksize))))]
    [(intext counter schedule state Nr-lidx istart iend aes-k-iv)
     (let crypt-block ([iidx : Nonnegative-Fixnum (assert istart fixnum?)])
       (when (< iidx iend)
         (aes-block-encrypt counter 0 aes-blocksize aes-k-iv 0 schedule state Nr-lidx)
         (aes-ctr-block-xor! intext iidx intext iidx aes-k-iv)
         (network-natural-bytes++ counter)
         (crypt-block (+ iidx aes-blocksize))))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-block-encrypt : (-> Bytes Index Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index Void)
  (lambda [plainblock pstart pend cipherblock cstart schedule state Nr-lidx]
    (aes-state-array-copy-from-bytes! state plainblock pstart pend)
    (aes-state-array-add-round-key! state schedule 00)
    
    (aes-step state aes-substitute-box schedule 04 #:encrypt)
    (aes-step state aes-substitute-box schedule 08 #:encrypt)
    (aes-step state aes-substitute-box schedule 12 #:encrypt)
    (aes-step state aes-substitute-box schedule 16 #:encrypt)
    (aes-step state aes-substitute-box schedule 20 #:encrypt)
    (aes-step state aes-substitute-box schedule 24 #:encrypt)
    (aes-step state aes-substitute-box schedule 28 #:encrypt)
    (aes-step state aes-substitute-box schedule 32 #:encrypt)
    (aes-step state aes-substitute-box schedule 36 #:encrypt)

    (let encrypt ([widx : Nonnegative-Fixnum 40])
      (when (< widx Nr-lidx)
        (aes-step state aes-substitute-box schedule widx #:encrypt)
        (encrypt (+ widx aes-Nb))))

    (aes-state-array-substitute! state aes-substitute-box)
    (aes-left-shift-rows! state)
    (aes-state-array-add-round-key! state schedule Nr-lidx)
    
    (aes-state-array-copy-to-bytes! state cipherblock cstart)))

(define aes-block-decrypt : (-> Bytes Index Index Bytes Nonnegative-Fixnum (Vectorof Nonnegative-Fixnum) (State-Array 4 4) Index Void)
  (lambda [cipherblock cstart cend plaintext pstart schedule state Nr-lidx]
    (aes-state-array-copy-from-bytes! state cipherblock cstart cend)
    (aes-state-array-add-round-key! state schedule Nr-lidx)

    (let encrypt ([widx : Fixnum (- Nr-lidx aes-Nb)])
      (when (>= widx 40)
        (aes-step state aes-inverse-substitute-box schedule widx #:decrypt)
        (encrypt (- widx aes-Nb))))

    (aes-step state aes-inverse-substitute-box schedule 36 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 32 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 28 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 24 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 20 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 16 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 12 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 08 #:decrypt)
    (aes-step state aes-inverse-substitute-box schedule 04 #:decrypt)

    (aes-state-array-substitute! state aes-inverse-substitute-box)
    (aes-right-shift-rows! state)
    (aes-state-array-add-round-key! state schedule 0)
    
    (aes-state-array-copy-to-bytes! state plaintext pstart)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-key-expand : (-> Bytes (Vectorof Nonnegative-Fixnum))
  (lambda [key]
    (define Nk : Byte (aes-words-size key))
    (define size : Index (aes-last-round-idx key 1))
    (define schedule : (Vectorof Nonnegative-Fixnum) (make-vector size))

    (let copy ([widx : Index 0])
      (when (< widx Nk)
        (define key-idx : Index (* widx 4))
        (vector-set! schedule widx (integer-bytes->uint32 key #false #true key-idx (+ key-idx 4)))
        (copy (+ widx 1))))
    
    (let expand ([widx : Nonnegative-Fixnum Nk])
      (when (< widx size)
        (define-values (i/Nk i%Nk) (quotient/remainder widx Nk))
        (define temp : Nonnegative-Fixnum
          (let ([temp (unsafe-vector-ref schedule (- widx 1))])
            (cond [(= i%Nk 0) (aes-substitute+rotate-word temp aes-substitute-box (aes-rcon i/Nk))]
                  [(and (> Nk 6) (= i%Nk 4)) (aes-substitute-word temp aes-substitute-box)]
                  [else temp])))
        
        (unsafe-vector-set! schedule widx (bitwise-xor (unsafe-vector-ref schedule (- widx Nk)) temp))
        
        (expand (+ widx 1))))
    
    schedule))

(define aes-key-schedule-rotate! : (-> (Vectorof Nonnegative-Fixnum) Void)
  (lambda [schedule]
    (define idxmax : Index (vector-length schedule))

    (let rotate ([idx : Nonnegative-Fixnum 0])
      (when (< idx idxmax)
        (define w1 : Nonnegative-Fixnum (unsafe-vector-ref schedule (+ idx 0)))
        (define w2 : Nonnegative-Fixnum (unsafe-vector-ref schedule (+ idx 1)))
        (define w3 : Nonnegative-Fixnum (unsafe-vector-ref schedule (+ idx 2)))
        (define w4 : Nonnegative-Fixnum (unsafe-vector-ref schedule (+ idx 3)))

        (unsafe-vector-set! schedule (+ idx 0)
                            (bitwise-ior (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w1 24) #xFF) 24)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w2 24) #xFF) 16)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w3 24) #xFF) 08)
                                         (unsafe-fxand                  (unsafe-fxrshift w4 24) #xFF)))

        (unsafe-vector-set! schedule (+ idx 1)
                            (bitwise-ior (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w1 16) #xFF) 24)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w2 16) #xFF) 16)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w3 16) #xFF) 08)
                                         (unsafe-fxand                  (unsafe-fxrshift w4 16) #xFF)))

        (unsafe-vector-set! schedule (+ idx 2)
                            (bitwise-ior (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w1 08) #xFF) 24)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w2 08) #xFF) 16)
                                         (unsafe-fxlshift (unsafe-fxand (unsafe-fxrshift w3 08) #xFF) 08)
                                         (unsafe-fxand                  (unsafe-fxrshift w4 08) #xFF)))
        
        (unsafe-vector-set! schedule (+ idx 3)
                            (bitwise-ior (unsafe-fxlshift (unsafe-fxand w1 #xFF) 24)
                                         (unsafe-fxlshift (unsafe-fxand w2 #xFF) 16)
                                         (unsafe-fxlshift (unsafe-fxand w3 #xFF) 08)
                                         (unsafe-fxand w4 #xFF)))
        
        (rotate (+ idx 4))))))

(define aes-ctr-block-xor! : (-> Bytes Index Bytes Nonnegative-Fixnum Bytes Void)
  (lambda [iblock istart oblock ostart cipher-K-IV]
    (define-values (inext istop) (values (+ istart 8) (+ istart 16)))
    (define ctr1 : Integer
      (bitwise-xor (integer-bytes->integer cipher-K-IV #false #true 0 8)
                   (integer-bytes->integer iblock #false #true istart inext)))
    (define ctr2 : Integer
      (bitwise-xor (integer-bytes->integer cipher-K-IV #false #true 8 16)
                   (integer-bytes->integer iblock #false #true inext istop)))

    (let ([onext (unsafe-fx+ ostart 8)])
      (integer->integer-bytes ctr1 8 #false #true oblock ostart)
      (integer->integer-bytes ctr2 8 #false #true oblock onext)
      (void))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-words-size : (-> Bytes Byte)
  (lambda [srckey]
    (assert (quotient (bytes-length srckey) 4) byte?)))

(define aes-last-round-idx : (->* (Bytes) ((U Zero One)) Index)
  (lambda [srckey [extra 0]]
    (* (assert (+ (+ (quotient (bytes-length srckey) 4) 6) extra) byte?) aes-Nb)))

(define aes-left-shift-rows! : (-> (State-Array 4 4) Void)
  (lambda [state]
    (aes-state-array-left-shift-word! state 1 0 08)
    (aes-state-array-left-shift-word! state 2 0 16)
    (aes-state-array-left-shift-word! state 3 0 24)
    (void)))

(define aes-right-shift-rows! : (-> (State-Array 4 4) Void)
  (lambda [state]
    (aes-state-array-right-shift-word! state 1 0 08)
    (aes-state-array-right-shift-word! state 2 0 16)
    (aes-state-array-right-shift-word! state 3 0 24)
    (void)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-substitute+rotate-word : (-> Nonnegative-Fixnum Bytes Byte Nonnegative-Fixnum)
  (lambda [temp s-box rc]
    (define w0 : Byte (unsafe-fxand (unsafe-fxrshift temp 24) #xFF))
    (define w1 : Byte (unsafe-fxand (unsafe-fxrshift temp 16) #xFF))
    (define w2 : Byte (unsafe-fxand (unsafe-fxrshift temp 08) #xFF))
    (define w3 : Byte (unsafe-fxand temp #xFF))

    (bitwise-ior (unsafe-fxlshift (unsafe-fxxor (unsafe-bytes-ref s-box w1) rc) 24)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w2) 16)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w3) 08)
                 (unsafe-bytes-ref s-box w0))))

(define aes-substitute-word : (-> Nonnegative-Fixnum Bytes Nonnegative-Fixnum)
  (lambda [temp s-box]
    (define w0 : Byte (unsafe-fxand (unsafe-fxrshift temp 24) #xFF))
    (define w1 : Byte (unsafe-fxand (unsafe-fxrshift temp 16) #xFF))
    (define w2 : Byte (unsafe-fxand (unsafe-fxrshift temp 08) #xFF))
    (define w3 : Byte (unsafe-fxand temp #xFF))

    (bitwise-ior (unsafe-fxlshift (unsafe-bytes-ref s-box w0) 24)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w1) 16)
                 (unsafe-fxlshift (unsafe-bytes-ref s-box w2) 08)
                 (unsafe-bytes-ref s-box w3))))

(define aes-rcon : (-> Index Byte)
  ;; https://en.wikipedia.org/wiki/Rijndael_key_schedule
  (let* ([prefab-rcs : (Vectorof Byte) (vector #x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36)]
         [prefab-size : Index (vector-length prefab-rcs)])
    (lambda [i]
      (cond [(<= i prefab-size) (unsafe-vector-ref prefab-rcs (- i 1))]
            [else (let 2rci-1 ([it : Nonnegative-Fixnum (max (- prefab-size 1) 0)]
                               [rc : Nonnegative-Fixnum (unsafe-vector-ref prefab-rcs (- prefab-size 1))])
                    (cond [(>= it i) (bitwise-and rc #xFF)]
                          [else (2rci-1 (+ it 1)
                                        (unsafe-fxxor (unsafe-fxlshift rc 1)
                                                      (if (< rc #x80) #x00 #x11B)))]))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-ciphertext-size : (-> Integer Natural)
  (lambda [plaintext-size]
    (define-values (q r) (quotient/remainder (max plaintext-size 0) aes-blocksize))

    (unsafe-fx+ (unsafe-fx* q aes-blocksize)
                (if (= r 0) 0 aes-blocksize))))
