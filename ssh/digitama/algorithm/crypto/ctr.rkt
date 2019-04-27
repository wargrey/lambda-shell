#lang typed/racket/base

(provide (all-defined-out))

(require racket/unsafe/ops)

(define ctr-block-xor! : (-> Bytes Index Bytes Index Bytes Byte Void)
  (lambda [iblock istart oblock ostart cipher-K-IV blocksize]
    (define xor-step : 8 8)
    (let ctr-xor ([cidx : Index 0]
                  [iidx : Nonnegative-Fixnum istart]
                  [oidx : Nonnegative-Fixnum ostart])
      (when (< cidx blocksize)
        (define cnext : Index (+ cidx xor-step))
        (define inext : Nonnegative-Fixnum (unsafe-fx+ iidx xor-step))
        (define onext : Nonnegative-Fixnum (unsafe-fx+ oidx xor-step))
        (define ctr : Integer
          (bitwise-xor (integer-bytes->integer cipher-K-IV #false #true cidx cnext)
                       (integer-bytes->integer iblock #false #true iidx inext)))

        (integer->integer-bytes ctr xor-step #false #true oblock oidx)
        (ctr-xor cnext inext onext)))))
