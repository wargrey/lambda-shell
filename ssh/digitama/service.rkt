#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

(require "../configuration.rkt")

(define-type SSH-Service-Layer-Reply (U SSH-Message (Listof SSH-Message) False))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Service-Constructor (-> Symbol SSH-User Bytes SSH-Service))
(define-type SSH-Service-Destructor (-> SSH-Service Void))

(define-type SSH-Service-Response (-> SSH-Service Bytes SSH-Configuration SSH-Service-Layer-Reply))
(define-type SSH-Service-Push-Evt (-> SSH-Service SSH-Configuration (Option (Evtof SSH-Service-Layer-Reply))))

(define-object ssh-service : SSH-Service
  ([name : Symbol]
   [user : SSH-User]
   [session : Bytes]
   [range : (Pairof Index Index)]
   [outgoing-log : (-> SSH-Message Void)])
  ([response : SSH-Service-Response]
   [push-evt : SSH-Service-Push-Evt ssh-service-no-evt]
   [destruct : SSH-Service-Destructor void]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Application-Constructor (-> Symbol Bytes SSH-Application))
(define-type SSH-Application-Destructor (-> SSH-Application Void))

(define-type SSH-Application-Transmit (-> SSH-Application SSH-Message SSH-Configuration (U SSH-Service-Layer-Reply (Boxof Any))))
(define-type SSH-Application-Deliver (-> SSH-Application Bytes SSH-Configuration (U SSH-Service-Layer-Reply (Boxof Any))))
(define-type SSH-Application-Data-Evt (-> SSH-Application SSH-Configuration (Option (Evtof SSH-Service-Layer-Reply))))

(define-object ssh-application : SSH-Application
  ([name : Symbol]
   [session : Bytes]
   [range : (Pairof Index Index)]
   [outgoing-log : (-> SSH-Message Void)])
  ([transmit : SSH-Application-Transmit]
   [deliver : SSH-Application-Deliver]
   [data-evt : SSH-Application-Data-Evt]
   [destruct : SSH-Application-Destructor void]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-no-evt : (-> (U SSH-Service SSH-Application) SSH-Configuration False)
  (lambda [self rfc]
    #false))