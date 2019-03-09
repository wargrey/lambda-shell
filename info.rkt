#lang info

(define collection 'multi)
(define pkg-desc "λsh is a scripting language for Windows and Unix administrators")
(define pkg-authors '(wargrey))

(define version "1.0")
(define deps '("base" "typed-racket-lib" "typed-racket-more"))
(define build-deps '("scribble-lib" "racket-doc"))
