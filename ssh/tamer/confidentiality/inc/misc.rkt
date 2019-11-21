#lang typed/racket/base

(provide (all-defined-out))

(require "../../../digitama/algorithm/crypto/utility.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define symb0x->octets : (-> Symbol Bytes)
  (lambda [i]
    (apply bytes
           (for/list : (Listof Byte) ([pair (in-list (regexp-match* #px".." (substring (symbol->string i) 2)))])
             (assert (string->number pair 16) byte?)))))

(define plaintext-0pad : (-> Bytes Byte Bytes)
  (lambda [raw blocksize]
    (define psize : Index (bytes-length raw))
    (define csize : Natural (ciphertext-size psize blocksize))
    (cond [(>= psize csize) raw]
          [else (let ([plaintext (make-bytes csize 0)])
                  (bytes-copy! plaintext 0 raw 0 psize)
                  plaintext)])))
