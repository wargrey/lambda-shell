#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

(require "../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> SSH-User Bytes SSH-Configuration SSH-Service))
(define-type SSH-Service-Destructor (-> SSH-Service Void))

(define-type SSH-Service-Response (-> SSH-Service Bytes (Values SSH-Service (U SSH-Message (Listof (U SSH-Message)) False))))
(define-type SSH-Service-Datum-Evt (-> SSH-Service (Option (Evtof (Pairof SSH-Service SSH-Message)))))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [session : Bytes]
   [preference : SSH-Configuration]
   [range : (Pairof Index Index)]
   [log-outgoing : (-> SSH-Message Void)])
  ([response : SSH-Service-Response]
   [datum-evt : SSH-Service-Datum-Evt ssh-service-no-evt]
   [destruct : SSH-Service-Destructor void]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-no-evt : (-> SSH-Service False)
  (lambda [self]
    #false))
