#lang racket/base

(provide (all-defined-out))
(provide (all-from-out "../message.rkt"))

(require "../message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-message
  (lambda [self]
    (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
      (define payload (ssh-message->bytes self))
      (values payload (ssh-bytes->message* payload)))))
