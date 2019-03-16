#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../../assignment.rkt"))

(require "packet.rkt")
(require "../../assignment.rkt")

(define ssh-read-transport-message : (-> Input-Port (U SSH-Message Bytes))
  (lambda [/dev/sshin]
    (define-values (payload mac) (ssh-read-binary-packet /dev/sshin 0))
    (or (ssh-bytes->message* payload ssh-msg-range/transport)
        payload)))
