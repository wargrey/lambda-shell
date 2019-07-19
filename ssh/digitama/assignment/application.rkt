#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

(require "../connection/application.rkt")

; datum definition: application-constructor

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-names #:application
  ; https://tools.ietf.org/html/rfc4252#section-5
  ([ssh-connection REQUIRED        #:=> make-ssh-connection-application]))
