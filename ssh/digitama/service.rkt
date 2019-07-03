#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> SSH-User Bytes SSH-Service))
(define-type SSH-Service-Destructor (-> SSH-Service Void))

(define-type SSH-Service-Response (-> SSH-Service SSH-Message (Values SSH-Service (U SSH-Message (Listof SSH-Message) EOF))))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [session : Bytes]
   [range? : (->* (Bytes) (Index) Boolean)])
  ([response : SSH-Service-Response]
   [destructor : SSH-Service-Destructor void]))
