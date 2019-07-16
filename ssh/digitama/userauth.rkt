#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "message.rkt")

(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Userauth-Constructor (-> Symbol Boolean SSH-Userauth))

(define-type SSH-Userauth-Request (-> SSH-Userauth Symbol Symbol (U SSH-Message Boolean) Bytes (Values SSH-Userauth (Option SSH-Message))))
(define-type SSH-Userauth-Response (-> SSH-Userauth SSH-Message Symbol Symbol Bytes (U SSH-Message SSH-Userauth-Option Boolean)))

(define-object ssh-userauth : SSH-Userauth
  ([name : Symbol])
  ([request : SSH-Userauth-Request]
   [response : SSH-Userauth-Response]))
