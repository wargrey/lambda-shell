#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")
(require "../../message.rkt")

(require (for-syntax "../../message.rkt"))

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST
  [PUBLICKEY 'publickey ([has-signature? : Boolean #false] [algorithm : String] [blob : String]) #:case has-signature?])

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST-PUBLICKEY
  [SIGNED    '#true ([signature : String])])
