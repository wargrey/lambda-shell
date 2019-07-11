#lang typed/racket/base

(provide (all-defined-out))

(require "../../message.rkt")

(require "../../message/connection.rkt")

(require "../../../datatype.rkt")

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require (for-syntax "../../message/connection.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-case-messages SSH-MSG-CHANNEL-OPEN
  ; https://tools.ietf.org/html/rfc4254#section-7.2
  [FORWARDED-TCPIP #:type 'forwarded-tcpip ([target-host : String] [target-port : Index] [originator-ip : String] [originator-port : Index])]
  [DIRECT-TCPIP    #:type 'direct-tcpip    ([target-host : String] [target-port : Index] [originator-ip : String] [originator-port : Index])])
