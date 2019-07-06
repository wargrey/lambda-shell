#lang typed/racket/base

(provide (for-syntax (all-defined-out)))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/string))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax (ssh-typename <id>)
  (format-id <id> "~a" (string-replace (symbol->string (syntax-e <id>)) "_" "-")))

(define-for-syntax (ssh-typename* <id> <id-suffix>)
  (syntax-case <id-suffix> []
    [(suffix) (ssh-typename (format-id <id-suffix> "~a~a" (syntax-e <id>) (syntax-e #'suffix)))]
    [suffix (ssh-typename (format-id <id-suffix> "~a_~a" (syntax-e <id>) (syntax-e #'suffix)))]))

(define-for-syntax (ssh-typeid <id>)
  (format-id <id> "~a" (string-replace (string-downcase (symbol->string (syntax-e <id>))) #px"[_-]" ":")))

(define-for-syntax (ssh-symname <id>)
  (format-id <id> "$~a" (syntax-e <id>)))

(define-for-syntax (ssh-symid <id>)
  (format-id <id> "#%~a" (syntax-e <id>)))
