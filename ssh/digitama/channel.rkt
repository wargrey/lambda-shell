#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Constructor (-> SSH-Message (U SSH-Channel SSH-Message)))

(struct ssh-channel
  ([name : Symbol])
  #:constructor-name make-ssh-channel
  #:type-name SSH-Channel)
