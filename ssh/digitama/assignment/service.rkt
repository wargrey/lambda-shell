#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

(require "../connection/service.rkt")

; datum definition: service-constructor

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-names #:service
  ; https://tools.ietf.org/html/rfc4252#section-5
  ([ssh-connection REQUIRED        #:=> make-ssh-connection-service]))
