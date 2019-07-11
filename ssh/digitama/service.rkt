#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> SSH-User Bytes SSH-Service))
(define-type SSH-Service-Destructor (-> SSH-Service Void))

(define-type SSH-Service-Response (-> SSH-Service Bytes (Values SSH-Service (U SSH-Message (Listof (U SSH-Message))))))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [session : Bytes]
   [range : (Pairof Index Index)])
  ([response : SSH-Service-Response]
   [destruct : SSH-Service-Destructor void]))
