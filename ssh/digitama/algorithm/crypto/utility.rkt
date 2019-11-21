#lang typed/racket/base

(provide (all-defined-out))

(require racket/unsafe/ops)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ciphertext-size : (-> Integer Byte Natural)
  (lambda [plaintext-size blocksize]
    (define-values (q r) (quotient/remainder (max plaintext-size 0) blocksize))

    (cond [(= r 0) (unsafe-fx* q blocksize)]
          [else (unsafe-fx+ (unsafe-fx* q blocksize) blocksize)])))
