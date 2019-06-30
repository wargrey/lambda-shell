#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")

(require "authentication/option.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Userauth-Constructor (-> Bytes SSH-Userauth))

(define-type SSH-Userauth-Request (-> SSH-Userauth Symbol Symbol (Option SSH-Message) SSH-Message))
(define-type SSH-Userauth-Response (-> SSH-Userauth SSH-Message Symbol Symbol (U SSH-Message SSH-Userauth-Option Boolean)))
(define-type SSH-Userauth-Abort (-> SSH-Userauth Void))

(struct ssh-userauth
  ([session-id : Bytes]
   [name : Symbol]
   [request : SSH-Userauth-Request]
   [response : SSH-Userauth-Response]
   [abort : (Option SSH-Userauth-Abort)])
  #:constructor-name make-ssh-userauth
  #:type-name SSH-Userauth)
