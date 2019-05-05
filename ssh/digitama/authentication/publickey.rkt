#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")
(require "../../message.rkt")

(require (for-syntax "../../message.rkt"))

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST
  [PUBLICKEY #:method 'publickey ([adequate? : Boolean #false] [algorithm : String] [blob : String]) #:case adequate?])

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST-PUBLICKEY
  [($)    #:adequate? '#true ([signature : String])])
