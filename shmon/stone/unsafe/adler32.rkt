#lang racket/base

(require digimon/ffi)

(define adler32-lib (digimon-ffi-lib "adler32"))

(define-ffi-definer define-adler32 adler32-lib)

(define-adler32 identity (_fun _int -> _int))

(identity 12)
