#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

(provide (all-defined-out))

(require "state.rkt")
(require "s-box.rkt")

(require racket/unsafe/ops)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-ctr : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (define Nb : Byte (aes-words-size IV))
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define S : State-Array (make-state-array Nb))
    (define key-schedule : Bytes (aes-key-expand key Nb))
    
    (values values values)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-key-expand : (-> Bytes Byte Bytes)
  (lambda [key Nb]
    (define Nk : Byte (aes-words-size key))
    (define Nr : Byte (aes-round Nk))
    (define size : Index (assert (unsafe-fx* Nb (+ Nr 1)) index?))
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
          (cond [(= i%Nk 0) (aes-subword tmp1 tmp2 tmp3 tmp0 aes-substitute-box (aes-rcon i/Nk))]
                [(and (> Nk 6) (= i%Nk 4)) (aes-subword tmp0 tmp1 tmp2 tmp3 aes-substitute-box)]
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

(define aes-subword : (case-> [Byte Byte Byte Byte Bytes Byte -> (Values Byte Byte Byte Byte)]
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
