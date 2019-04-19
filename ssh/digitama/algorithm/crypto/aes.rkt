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
    (define Nb : Byte (aes-words-size IV))
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define state : State-Array (make-state-array 4 Nb))
    (define key-schedule : (Vectorof Natural) (aes-key-expand key Nb))

    (aes-key-schedule-rotate! key-schedule)
    (values (λ [[plaintext : Bytes]] : Bytes (aes-encrypt-ctr plaintext key-schedule state Nb Nr))
            (λ [[ciphertext : Bytes]] : Bytes (aes-decrypt-ctr ciphertext key-schedule state Nb Nr)))))

(define aes-encrypt-ctr : (-> Bytes (Vectorof Natural) State-Array Byte Byte Bytes)
  (lambda [plaintext schedule state wordstep round]
    (define blocksize : Index (* wordstep 4))
    (define size : Index (bytes-length plaintext))
    (define ciphertext : Bytes (make-bytes size))

    (let encrypt-block ([block-idx : Nonnegative-Fixnum 0])
      (when (< block-idx size)
        (aes-block-encrypt-ctr! plaintext ciphertext block-idx schedule state wordstep round)
        (encrypt-block (+ block-idx blocksize))))

    ciphertext))

(define aes-decrypt-ctr : (-> Bytes (Vectorof Natural) State-Array Byte Byte Bytes)
  (lambda [ciphertext schedule state wordstep round]
    ciphertext))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-block-encrypt-ctr : (->* (Bytes (Vectorof Natural) State-Array Byte Byte) (Index) Bytes)
  (lambda [inblock schedule state wordstep round [instart 0]]
    (define outblock : Bytes (make-bytes (state-array-blocksize state)))
    
    (aes-block-encrypt-ctr! inblock outblock instart schedule state wordstep round 0)
    outblock))

(define aes-block-encrypt-ctr! : (->* (Bytes Bytes Index (Vectorof Natural) State-Array Byte Byte) ((Option Index)) Natural)
  (lambda [inblock outblock instart schedule state wordstep round [maybe-outstart #false]]
    (define outstart : Index (or maybe-outstart instart))
    (define last-round-idx : Index (* wordstep round))
    
    (state-array-copy-from-bytes! state inblock instart)
    (state-array-add-round-key! state schedule 0)

    (let encrypt ([widx : Nonnegative-Fixnum wordstep])
      (when (< widx last-round-idx)
        (state-array-substitute! state aes-substitute-box)
        (aes-shift-rows! state)
        (aes-mix-columns! state)
        (state-array-add-round-key! state schedule widx)
        
        (encrypt (+ widx wordstep))))

    (state-array-substitute! state aes-substitute-box)
    (aes-shift-rows! state)
    (state-array-add-round-key! state schedule last-round-idx)
    
    (state-array-copy-to-bytes! state outblock outstart)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-key-expand : (-> Bytes Byte (Vectorof Natural))
  (lambda [key Nb]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define size : Index (assert (unsafe-fx* Nb (+ Nr 1)) index?))
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
