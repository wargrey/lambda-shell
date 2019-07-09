#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; https://tools.ietf.org/html/rfc4251#section-7
(define-ssh-message-range transport        1  49   Transport layer protocol)
(define-ssh-message-range authentication  50  79   User authentication protocol)
(define-ssh-message-range connection      80 127   Connection protocol)
(define-ssh-message-range client         128 191   Reserved for client protocols)
(define-ssh-message-range private        192 255   Local extensions for private use)

(define-ssh-message-range generic          1  19   Transport layer generic (e.g., disconnect, ignore, debug, etc.))
(define-ssh-message-range kex             30  49   Key exchange method specific (numbers can be reused for different authentication methods))
