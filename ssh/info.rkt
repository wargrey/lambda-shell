#lang info

(define collection 'use-pkg-name)
(define pkg-authors '(wargrey))

(define software-version 'λsh_SSH)

(define version "1.0")
(define deps '("base" "typed-racket-lib" "typed-racket-more"))
(define build-deps '("scribble-lib" "racket-doc"))

(define scribblings '(["tamer/ssh.scrbl" (main-doc) (net-library)]))
