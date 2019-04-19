#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../digitama/algorithm/crypto/aes.rkt"))
(provide (all-from-out "../digitama/algorithm/crypto/state.rkt"))

(require "../digitama/algorithm/crypto/aes.rkt")
(require "../digitama/algorithm/crypto/state.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-mixcolumns! : (-> State-Array Void)
  (lambda [state]
    (aes-mix-columns! state 0 #:encrypt)
    (aes-mix-columns! state 1 #:encrypt)
    (aes-mix-columns! state 2 #:encrypt)
    (aes-mix-columns! state 3 #:encrypt)))
