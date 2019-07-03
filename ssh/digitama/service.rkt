#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> SSH-User Bytes SSH-Service))
(define-type SSH-Service-Destructor (-> SSH-Service Void))

(define-type SSH-Service-Response (-> SSH-Service SSH-Message (Values SSH-Service (U SSH-Message (Listof SSH-Message) EOF))))
(define-type SSH-Service-Shared-Message-Group (-> SSH-Service (Option (Listof Symbol))))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [session : Bytes]
   [bytes->message : (->* (Bytes) (Index #:groups (Listof Symbol)) (Values (Option SSH-Message) Natural))])
  ([response : SSH-Service-Response]
   [shared-message-group : SSH-Service-Shared-Message-Group ssh-service-shared-message-group/none]
   [destructor : SSH-Service-Destructor void]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-shared-message-group/none : SSH-Service-Shared-Message-Group
  (lambda [self]
    #false))

(define ssh-service-shared-message-group/identity : SSH-Service-Shared-Message-Group
  (lambda [self]
    (list (ssh-service-name self))))
