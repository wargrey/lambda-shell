#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf 
;;; https://en.wikipedia.org/wiki/Finite_field_arithmetic

(provide (all-defined-out))

(require racket/unsafe/ops)

(struct state-array
  ([rows : Byte]
   [cols : Byte]
   [pool : Bytes])
  #:type-name State-Array)

(define make-state-array : (-> Byte Byte State-Array)
  (lambda [rows Nb]
    (state-array rows Nb (make-bytes (* Nb rows)))))

(define make-state-array-from-bytes : (->* (Byte Byte Bytes) (Index) State-Array)
  (lambda [rows Nb src [start 0]]
    (define s : State-Array (make-state-array rows Nb))

    (state-array-copy-from-bytes! s src start)
    s))

(define make-bytes-from-state-array : (-> State-Array Bytes)
  (lambda [s]
    (define block : Bytes (make-bytes (state-array-blocksize s)))

    (state-array-copy-to-bytes! s block 0)
    block))

(define state-array-copy-from-bytes! : (->* (State-Array Bytes) (Index) Void)
  (lambda [s in [start 0]]
    (define-values (row col) (state-array-size s))
    (define pool : Bytes (state-array-pool s))
    (define blocksize : Index (* row col))
    (define total : Index (bytes-length in))
    (define padding : Fixnum (- (+ start blocksize) total))
    (define maxidx : Index (if (> padding 0) (assert (- blocksize padding) index?) blocksize))

    (when (> padding 0) ; TODO: Perhaps it is not a good idea to pad here 
      (bytes-fill! pool padding))

    (let copy-in ([idx : Nonnegative-Fixnum 0])
      (when (< idx maxidx)
        (define c : Index (unsafe-fxquotient idx row))
        (define r : Byte (unsafe-fxremainder idx row))
        
        (unsafe-bytes-set! pool (+ c (* col r)) (unsafe-bytes-ref in (unsafe-fx+ idx start)))
        (copy-in (+ idx 1))))))

(define state-array-copy-to-bytes! : (->* (State-Array Bytes) (Index) Void)
  (lambda [s out [start 0]]
    (define-values (row col) (state-array-size s))
    (define pool : Bytes (state-array-pool s))
    (define blocksize : Index (* row col))
    (define capacity : Index (bytes-length out))
    (define truncated : Fixnum (- (+ start blocksize) capacity))
    (define maxidx : Index (if (> truncated 0) (assert (- blocksize truncated) index?) blocksize))

    (let copy-out ([idx : Nonnegative-Fixnum 0])
      (when (< idx maxidx)
        (define c : Index (unsafe-fxquotient idx row))
        (define r : Byte (unsafe-fxremainder idx row))
        
        (unsafe-bytes-set! out (unsafe-fx+ idx start) (unsafe-bytes-ref pool (+ c (* col r))))
        (copy-out (+ idx 1))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define state-array-size : (-> State-Array (Values Byte Byte))
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

(define state-array-add-round-key! : (-> State-Array (Vectorof Natural) Nonnegative-Fixnum Void)
  (lambda [s rotated-schedule start]
    (define-values (row col) (state-array-size s))
    (define pool : Bytes (state-array-pool s))

    (let add-round-key ([r : Index 0])
      (when (< r row)
        (define s-idx : Fixnum (unsafe-fx* col r))
        (define self : Natural (integer-bytes->integer pool #false #true s-idx (unsafe-fx+ s-idx 4)))
        (define keyv : Natural (vector-ref rotated-schedule (unsafe-fx+ r start)))

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

(define state-array-left-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Integer (+ (* wc 4) (* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (+ idx 4)))

    (integer->integer-bytes (bitwise-ior (bitwise-and (arithmetic-shift v bits) #xFFFFFFFF) (arithmetic-shift v (- bits 32)))
                            4 #false #true pool idx)

    (void)))

(define unsafe-state-array-left-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Fixnum (unsafe-fx+ (unsafe-fx* wc 4) (unsafe-fx* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (unsafe-fx+ idx 4)))

    (integer->integer-bytes (unsafe-fxxor (unsafe-fxand (unsafe-fxlshift v bits) #xFFFFFFFF) (unsafe-fxrshift v (- 32 bits)))
                            4 #false #true pool idx)

    (void)))

(define state-array-right-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Integer (+ (* wc 4) (* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (+ idx 4)))

    (integer->integer-bytes (bitwise-ior (arithmetic-shift v (- bits)) (bitwise-and (arithmetic-shift v (- 32 bits)) #xFFFFFFFF))
                            4 #false #true pool idx)

    (void)))

(define unsafe-state-array-right-shift-word! : (-> State-Array Integer Integer Byte Void)
  (lambda [s r wc bits]
    (define pool : Bytes (state-array-pool s))
    (define idxmax : Index (bytes-length pool))

    (define idx : Fixnum (unsafe-fx+ (unsafe-fx* wc 4) (unsafe-fx* (state-array-rows s) r)))
    (define v : Integer (integer-bytes->integer pool #false #true idx (unsafe-fx+ idx 4)))

    (integer->integer-bytes (unsafe-fxxor (unsafe-fxrshift v bits) (unsafe-fxand (unsafe-fxlshift v (- 32 bits)) #xFFFFFFFF))
                            4 #false #true pool idx)

    (void)))
