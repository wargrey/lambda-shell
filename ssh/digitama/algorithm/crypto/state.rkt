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

(define make-state-array : (-> Byte Index State-Array)
  (lambda [rows Nb]
    (state-array rows Nb (make-bytes (* Nb rows)))))

(define make-state-array-from-bytes : (->* (Byte Index Bytes) (Natural) State-Array)
  (lambda [rows Nb src [start 0]]
    (define s : State-Array (make-state-array rows Nb))

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
    (define pool : Bytes (state-array-pool s))
    (define end : Natural (+ start (* row col)))

    
    (let copy-row ([r : Index 0])
      (when (< r row)
        (define rn : Nonnegative-Fixnum (unsafe-fx+ r start))
        (let copy-col ([c : Nonnegative-Fixnum 0])
          (when (< c col)
            (unsafe-bytes-set! pool
                               (unsafe-fx+ c (unsafe-fx* col r))
                               (bytes-ref in (unsafe-fx+ rn (unsafe-fx* row c))))
            (copy-col (+ c 1))))
        (copy-row (+ r 1))))
      
    end))

(define state-array-copy-to-bytes! : (->* (State-Array Bytes) (Natural) Natural)
  (lambda [s out [start 0]]
    (define-values (row col) (state-array-size s))
    (define pool : Bytes (state-array-pool s))
    (define end : Natural (+ start (* row col)))

    (let copy-row ([r : Index 0])
      (when (< r row)
        (define rn : Nonnegative-Fixnum (unsafe-fx+ r start))
        (let copy-col ([c : Nonnegative-Fixnum 0])
          (when (< c col)
            (bytes-set! out
                        (unsafe-fx+ rn (unsafe-fx* row c))
                        (unsafe-bytes-ref pool (unsafe-fx+ c (unsafe-fx* col r))))
            (copy-col (+ c 1))))
        (copy-row (+ r 1))))  

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
                (+ c (* (state-array-cols s) r))
                v)))

(define unsafe-state-array-set! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r c v]
    (unsafe-bytes-set! (state-array-pool s)
                       (unsafe-fx+ c (unsafe-fx* (state-array-cols s) r))
                       v)))

(define state-array-ref : (-> State-Array Integer Integer Byte)
  (lambda [s r c]
    (bytes-ref (state-array-pool s)
               (+ c (* (state-array-cols s) r)))))

(define unsafe-state-array-ref : (-> State-Array Integer Integer Byte)
  (lambda [s r c]
    (unsafe-bytes-ref (state-array-pool s)
                      (unsafe-fx+ c (unsafe-fx* (state-array-cols s) r)))))

(define state-array-add-round-key! : (-> State-Array (Vectorof Natural) Index Void)
  (lambda [s rotated-schedule start]
    (define-values (row col) (state-array-size s))
    (define pool : Bytes (state-array-pool s))

    (let add-round-key ([r : Index 0])
      (when (< r row)
        (define s-idx : Fixnum (unsafe-fx* col r))
        (define self : Natural (integer-bytes->integer pool #false #true s-idx (unsafe-fx+ s-idx 4)))
        (define keyv : Natural (vector-ref rotated-schedule (+ r start)))

        (integer->integer-bytes (bitwise-xor self keyv) 4 #false #true pool s-idx)
        
        (add-round-key (+ r 1))))))

(define state-array-substitute! : (-> State-Array Bytes Void)
  (lambda [s s-box]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (let substitute ([idx : Nonnegative-Fixnum 0])
      (when (< idx idxmax)
        (unsafe-bytes-set! pool idx (unsafe-bytes-ref s-box (unsafe-bytes-ref pool idx)))
        (substitute (+ idx 1))))))

(define state-array-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Integer (+ (* wc 4) (* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (+ idx 4)))

    (integer->integer-bytes (bitwise-ior (bitwise-and (arithmetic-shift v bits) #xFFFFFFFF) (arithmetic-shift v (- bits 32)))
                            4 #false #true pool idx)

    (void)))

(define unsafe-state-array-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Fixnum (unsafe-fx+ (unsafe-fx* wc 4) (unsafe-fx* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (unsafe-fx+ idx 4)))

    (integer->integer-bytes (unsafe-fxxor (unsafe-fxand (unsafe-fxlshift v bits) #xFFFFFFFF) (unsafe-fxrshift v (- 32 bits)))
                            4 #false #true pool idx)

    (void)))
