#lang racket/base

(require digimon/ffi)

(define adler32-lib (digimon-ffi-lib "adler32"))

(define-ffi-definer define-adler32 adler32-lib)

(define-adler32 adler32_base (_fun -> _ulong))

(adler32_base)
