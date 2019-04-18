#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

(provide (all-defined-out))

(require "state.rkt")
(require "s-box.rkt")
(require "math.rkt")

(require racket/unsafe/ops)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-ctr : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (define blocksize : Index (bytes-length IV))
    (define Nb : Byte (aes-words-size IV))
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 Nb))
    (define key-schedule : Bytes (aes-key-expand key Nb))
    
    (values (λ [[plaintext : Bytes]] : Bytes (aes-encrypt-ctr plaintext key-schedule state blocksize Nr))
            (λ [[ciphertext : Bytes]] : Bytes (aes-decrypt-ctr ciphertext key-schedule state blocksize Nr)))))

(define aes-encrypt-ctr : (-> Bytes Bytes State-Array Index Byte Bytes)
  (lambda [plaintext schedule state blocksize round]
    (define size : Index (bytes-length plaintext))
    (define ciphertext : Bytes (make-bytes size))

    (let encrypt-block ([block-idx : Nonnegative-Fixnum 0])
      (when (< block-idx size)
        (aes-block-encrypt-ctr! plaintext ciphertext block-idx schedule state blocksize round)
        (encrypt-block (+ block-idx blocksize))))

    ciphertext))

(define aes-decrypt-ctr : (-> Bytes Bytes State-Array Index Byte Bytes)
  (lambda [ciphertext schedule state blocksize round]
    ciphertext))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-block-encrypt-ctr : (->* (Bytes Bytes State-Array Index Byte) (Index) Bytes)
  (lambda [inblock schedule state blocksize round [instart 0]]
    (define outblock : Bytes (make-bytes (state-array-blocksize state)))
    
    (aes-block-encrypt-ctr! inblock outblock instart schedule state blocksize round 0)
    outblock))

(define aes-block-encrypt-ctr! : (->* (Bytes Bytes Index Bytes State-Array Index Byte) ((Option Index)) Natural)
  (lambda [inblock outblock instart schedule state blocksize round [maybe-outstart #false]]
    (define outstart : Index (or maybe-outstart instart))
    (define last-round-idx : Index (assert (+ instart (* blocksize round)) index?))
    
    (state-array-copy-from-bytes! state inblock instart)
    (state-array-add-round-key! state schedule 0)

    (let encrypt ([widx : Nonnegative-Fixnum (+ instart blocksize)])
      (when (< widx last-round-idx)
        (state-array-substitute! state aes-substitute-box)
        (aes-shift-rows! state)
        (aes-mix-columns! state)
        (state-array-add-round-key! state schedule widx)
        
        (encrypt (+ widx blocksize))))

    (state-array-substitute! state aes-substitute-box)
    (aes-shift-rows! state)
    (state-array-add-round-key! state schedule last-round-idx)
    
    (state-array-copy-to-bytes! state outblock outstart)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-key-expand : (-> Bytes Byte Bytes)
  (lambda [key Nb]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define size : Index (assert (unsafe-fx* (unsafe-fx* 4 Nb) (+ Nr 1)) index?))
    (define schedule : Bytes (make-bytes size))
    
    (bytes-copy! schedule 0 key)
    (let expand ([widx : Nonnegative-Fixnum (* Nk 4)]
                 [i-Nk : Natural 0])
      (when (< widx size)
        (define-values (i/Nk i%Nk) (quotient/remainder (quotient widx 4) Nk))
        (define-values (tmp0 tmp1 tmp2 tmp3)
          (values (unsafe-bytes-ref schedule (- widx 4))
                  (unsafe-bytes-ref schedule (- widx 3))
                  (unsafe-bytes-ref schedule (- widx 2))
                  (unsafe-bytes-ref schedule (- widx 1))))
        (define-values (xor0 xor1 xor2 xor3)
          (cond [(= i%Nk 0) (aes-substitute-word tmp1 tmp2 tmp3 tmp0 aes-substitute-box (aes-rcon i/Nk))]
                [(and (> Nk 6) (= i%Nk 4)) (aes-substitute-word tmp0 tmp1 tmp2 tmp3 aes-substitute-box)]
                [else (values tmp0 tmp1 tmp2 tmp3)]))
        
        (unsafe-bytes-set! schedule (+ widx 0) (bitwise-xor (unsafe-bytes-ref schedule (+ i-Nk 0)) xor0))
        (unsafe-bytes-set! schedule (+ widx 1) (bitwise-xor (unsafe-bytes-ref schedule (+ i-Nk 1)) xor1))
        (unsafe-bytes-set! schedule (+ widx 2) (bitwise-xor (unsafe-bytes-ref schedule (+ i-Nk 2)) xor2))
        (unsafe-bytes-set! schedule (+ widx 3) (bitwise-xor (unsafe-bytes-ref schedule (+ i-Nk 3)) xor3))
        
        (expand (+ widx 4) (unsafe-fx+ i-Nk 4))))
    
    schedule))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-words-size : (-> Bytes Byte)
  (lambda [src]
    (assert (quotient (bytes-length src) 4) byte?)))

(define aes-round : (-> Byte Byte)
  (lambda [Nk]
    (assert (+ Nk 6) byte?)))

(define aes-shift-rows! : (-> State-Array Void)
  (lambda [state]
    (state-array-shift-word! state 1 0 08)
    (state-array-shift-word! state 2 0 16)
    (state-array-shift-word! state 3 0 24)))

(define aes-mix-columns! : (-> State-Array Void)
  (lambda [state]
    (let mix-col ([c : Index 0])
      (when (< c 4)
        (define s0c : Byte (state-array-ref state 0 c))
        (define s1c : Byte (state-array-ref state 1 c))
        (define s2c : Byte (state-array-ref state 2 c))
        (define s3c : Byte (state-array-ref state 3 c))

        (state-array-set! state 0 c (byte+ (byte* #x02 s0c) (byte* #x03 s1c) s2c s3c))
        (state-array-set! state 1 c (byte+ s0c (byte* #x02 s1c) (byte* #x03 s2c) s3c))
        (state-array-set! state 2 c (byte+ s0c s1c (byte* #x02 s2c) (byte* #x03 s3c)))
        (state-array-set! state 3 c (byte+ (byte* #x03 s0c) s1c s2c (byte* #x02 s3c)))
        
        (mix-col (+ c 1))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-substitute-word : (case-> [Byte Byte Byte Byte Bytes Byte -> (Values Byte Byte Byte Byte)]
                              [Byte Byte Byte Byte Bytes -> (Values Byte Byte Byte Byte)])
  (case-lambda
    [(w0 w1 w2 w3 s-box rc)
     (values (bitwise-xor (unsafe-bytes-ref s-box w0) rc)
             (unsafe-bytes-ref s-box w1)
             (unsafe-bytes-ref s-box w2)
             (unsafe-bytes-ref s-box w3))]
    [(w0 w1 w2 w3 s-box)
     (values (unsafe-bytes-ref s-box w0)
             (unsafe-bytes-ref s-box w1)
             (unsafe-bytes-ref s-box w2)
             (unsafe-bytes-ref s-box w3))]))

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
                                        (bitwise-xor (unsafe-fxlshift rc 1)
                                                   (if (< rc #x80) #x00 #x11B)))]))]))))
