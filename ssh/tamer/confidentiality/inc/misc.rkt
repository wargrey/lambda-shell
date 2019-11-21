#lang typed/racket/base

(provide (all-defined-out))

(define symb0x->octets : (-> Symbol Bytes)
  (lambda [i]
    (apply bytes
           (for/list : (Listof Byte) ([pair (in-list (regexp-match* #px".." (substring (symbol->string i) 2)))])
             (assert (string->number pair 16) byte?)))))
