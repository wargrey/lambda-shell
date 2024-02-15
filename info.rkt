#lang info

(define collection 'multi)
(define pkg-desc "λsh is a scripting language for Windows and Unix administrators")
(define pkg-authors '(wargrey))
(define version "1.0")

(define deps '("base" "digimon" "typed-racket-lib" "typed-racket-more" "scribble-lib" "graphics" "math-lib"))
(define build-deps '("digimon" "scribble-lib" "graphics" "math-lib" "racket-doc"))
(define test-omit-paths 'all)
