#lang typed/racket/base

(provide (all-defined-out))

(require "pi-box.rkt")
(require "encryption.rkt")

(require racket/vector)
(require racket/unsafe/ops)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define blowfish-make-boxes : (-> Bytes (Values (Vectorof Nonnegative-Fixnum) (Vectorof Natural)))
  (lambda [key]
    (define psize : Byte (assert (vector-length parray) byte?))
    (define P : (Vectorof Nonnegative-Fixnum) (make-vector psize))
    (define S : (Vectorof Natural) (vector-append sbox0 sbox1 sbox2 sbox3))
    (define ssize : Index (vector-length S))
    (define ksize : Index (bytes-length key))
    
    (let P-xor ([pidx : Index 0]
                [kidx : Index 0])
      (when (< pidx psize)
        (define-values (k kidx++) (bf-key-ref key kidx ksize))
        (unsafe-vector-set! P pidx (unsafe-fxxor (unsafe-vector-ref parray pidx) k))
        (P-xor (+ pidx 1) kidx++)))

    (define-values (L R)
      (let P-replace : (Values Nonnegative-Fixnum Nonnegative-Fixnum)
        ([pidx : Index 0]
         [L : Nonnegative-Fixnum 0]
         [R : Nonnegative-Fixnum 0])
        (cond [(>= pidx psize) (values L R)]
              [else (let-values ([(l r) (bf-encrypt L R P S)])
                      (unsafe-vector-set! P pidx l)
                      (unsafe-vector-set! P (+ pidx 1) r)
                      (P-replace (+ pidx 2) l r))])))

    (let S-replace ([sidx : Nonnegative-Fixnum 0]
                    [L : Nonnegative-Fixnum L]
                    [R : Nonnegative-Fixnum R])
      (when (< sidx ssize)
        (define-values (l r) (bf-encrypt L R P S))
        (unsafe-vector-set! S sidx l)
        (unsafe-vector-set! S (+ sidx 1) r)
        (S-replace (+ sidx 2) l r)))
    
    (values P S)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define bf-key-ref : (-> Bytes Index Index (Values Natural Index))
  (lambda [key idx end]
    (define kidx++ : Nonnegative-Fixnum (+ idx 4))
    (cond [(< kidx++ end) (values (integer-bytes->integer key #false #true idx kidx++) kidx++)]
          [(= kidx++ end) (values (integer-bytes->integer key #false #true idx kidx++) 0)]
          [(= (- kidx++ end) 4) (values 0 0)] ; key is ""
          [else (let*-values ([(k0 i++) (values (unsafe-bytes-ref key idx) (remainder (+ idx 1) end))]
                              [(k1 i++) (values (unsafe-bytes-ref key i++) (remainder (+ i++ 1) end))]
                              [(k2 i++) (values (unsafe-bytes-ref key i++) (remainder (+ i++ 1) end))]
                              [(k3 i++) (values (unsafe-bytes-ref key i++) (remainder (+ i++ 1) end))])
                  (values (unsafe-fxior (unsafe-fxior (unsafe-fxlshift k2 08) k3)
                                        (unsafe-fxior (unsafe-fxlshift k0 24)
                                                      (unsafe-fxlshift k1 16)))
                          i++))])))
