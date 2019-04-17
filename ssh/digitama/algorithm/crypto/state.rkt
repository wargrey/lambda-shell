#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf 
;;; https://en.wikipedia.org/wiki/Finite_field_arithmetic

(provide (all-defined-out))

(require racket/unsafe/ops)

(struct state-array
  ([rows : Byte]
   [cols : Index]
   [pool : Bytes])
  #:type-name State-Array)

(define make-state-array : (-> Index State-Array)
  (lambda [Nb]
    (state-array 4 Nb (make-bytes (* Nb 4)))))

(define make-state-array-from-bytes : (->* (Index Bytes) (Natural) State-Array)
  (lambda [Nb src [start 0]]
    (define s : State-Array (make-state-array Nb))

    (state-array-copy-from-bytes! s src start)
    s))

(define make-bytes-from-state-array : (-> State-Array Bytes)
  (lambda [s]
    (define block : Bytes (make-bytes (state-array-blocksize s)))

    (state-array-copy-to-bytes! s block 0)
    block))

(define state-array-copy-from-bytes! : (->* (State-Array Bytes) (Natural) Natural)
  (lambda [s in [start 0]]
    (define-values (row col) (state-array-size s))
    (define end : Natural (+ start (* row col)))

    (bytes-copy! (state-array-pool s) 0 in start end)
      
    end))

(define state-array-copy-to-bytes! : (->* (State-Array Bytes) (Natural) Natural)
  (lambda [s out [start 0]]
    (define-values (row column) (state-array-size s))
    (define end : Natural (+ start (* row column)))

    (bytes-copy! out start (state-array-pool s))  

    end))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define state-array-size : (-> State-Array (Values Byte Index))
  (lambda [s]
    (values (state-array-rows s)
            (state-array-cols s))))

(define state-array-blocksize : (-> State-Array Index)
  (lambda [s]
    (define-values (row column) (state-array-size s))

    (assert (* row column) index?)))

(define state-array-set! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r c v]
    (bytes-set! (state-array-pool s)
                (+ r (* (state-array-rows s) c))
                v)))

(define unsafe-state-array-set! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r c v]
    (unsafe-bytes-set! (state-array-pool s)
                       (unsafe-fx+ r (unsafe-fx* (state-array-rows s) c))
                       v)))

(define state-array-ref : (-> State-Array Integer Integer Byte)
  (lambda [s r c]
    (bytes-ref (state-array-pool s)
               (+ r (* (state-array-rows s) c)))))

(define unsafe-state-array-ref : (-> State-Array Integer Integer Byte)
  (lambda [s r c]
    (unsafe-bytes-ref (state-array-pool s)
                      (unsafe-fx+ r (unsafe-fx* (state-array-rows s) c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Add two numbers in the GF(2^8) finite field
(define byte+ : (-> Byte Byte Byte)
  (lambda [n1 n2]
    (bitwise-xor n1 n2)))

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
