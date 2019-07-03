#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> SSH-User SSH-Service))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [range? : (->* (Bytes) (Index) Boolean)])
  ())
