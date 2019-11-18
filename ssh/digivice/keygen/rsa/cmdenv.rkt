#lang typed/racket/base

(provide (all-defined-out))

(define sshkey-rsa-bits : (Parameterof Positive-Index) (make-parameter 2048))
(define sshkey-rsa-public-exponent : (Parameterof Positive-Integer) (make-parameter 65537))
