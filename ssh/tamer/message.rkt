#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../message.rkt"))

(require "../message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-message : (-> SSH-Message (Values Bytes SSH-Message))
  (lambda [self]
    (define payload (ssh-message->bytes self))
    (values payload (ssh-bytes->message* payload))))
