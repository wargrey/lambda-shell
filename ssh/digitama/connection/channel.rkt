#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "../message.rkt")

(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Constructor (-> Symbol SSH-Message SSH-Configuration (U SSH-Channel SSH-Message)))

(define-type SSH-Channel-Response (-> SSH-Channel SSH-Message Index Boolean SSH-Configuration (Values SSH-Channel (U SSH-Message (Listof (U SSH-Message)) False))))

(define-object ssh-channel : SSH-Channel
  ([name : Symbol]
   [envariables : Environment-Variables]
   [custodian : Custodian])
  ([response : SSH-Channel-Response]))
