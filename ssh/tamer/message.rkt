#lang racket/base

(require "../message.rkt")

(provide (all-defined-out))

(define ssh-message
  (lambda [self]
    (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
      (define payload (ssh-message->bytes self))
      (values payload (ssh-bytes->message* payload)))))
