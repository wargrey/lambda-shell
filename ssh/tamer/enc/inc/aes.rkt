#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../../../digitama/algorithm/crypto/aes.rkt"))

(require "../../../digitama/algorithm/crypto/aes.rkt")
(require "../../../digitama/algorithm/crypto/state.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-mixcolumns! : (-> (State-Array 4 4) Void)
  (lambda [state]
    (aes-mix-columns! state 0 #:encrypt)
    (aes-mix-columns! state 1 #:encrypt)
    (aes-mix-columns! state 2 #:encrypt)
    (aes-mix-columns! state 3 #:encrypt)))

(define aes-state-add-round-key! : (-> (State-Array 4 4) (Vectorof Nonnegative-Fixnum) Byte Void)
  (lambda [state schedule start]
    (aes-state-array-add-round-key! state schedule start)
    (void)))
