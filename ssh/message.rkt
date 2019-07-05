#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Message Unsafe-SSH-Bytes->Message)
(provide ssh-message? ssh-message-undefined?)
(provide ssh-message-number ssh-message-name ssh-message-payload-number ssh-message-length)
(provide ssh-message->bytes ssh-bytes->message ssh-bytes->message*)
(provide define-ssh-messages define-ssh-case-messages define-ssh-shared-messages define-ssh-message-range)

(provide (all-from-out "digitama/assignment/message.rkt"))

(require "digitama/message.rkt")
(require "digitama/assignment/message.rkt")
