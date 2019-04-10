#lang typed/racket/base

(provide (all-defined-out))

(define ssh-keyfile : (Parameterof (Option Path-String)) (make-parameter #false))
