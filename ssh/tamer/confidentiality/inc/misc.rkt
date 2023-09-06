#lang typed/racket/base

(provide (all-defined-out))

(require "../../../digitama/algorithm/crypto/utility.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define plaintext-0pad : (-> Bytes Byte Bytes)
  (lambda [raw blocksize]
    (define psize : Index (bytes-length raw))
    (define csize : Natural (ciphertext-size psize blocksize))
    (cond [(>= psize csize) raw]
          [else (let ([plaintext (make-bytes csize 0)])
                  (bytes-copy! plaintext 0 raw 0 psize)
                  plaintext)])))
