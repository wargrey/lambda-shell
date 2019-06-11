#lang racket/base

(require digimon/ffi)

(define user-lib (digimon-ffi-lib "user"))

(define-ffi-definer define-user user-lib)

(define-user identity (_fun _int -> _int))

(identity 12)
