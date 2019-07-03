#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")
(require "../algorithm/random.rkt")

(require "../assignment.rkt")
(require "../../assignment.rkt")
(require "../../datatype.rkt")

;; [60, 79] can be reused for different user authentication methods
;; see digitama/authentication/publickey

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4252
  [SSH_MSG_USERAUTH_REQUEST          50 ([username : Symbol] [service : Symbol 'ssh-connection] [method : Symbol 'none]) #:case method]
  [SSH_MSG_USERAUTH_FAILURE          51 ([methods : (SSH-Name-Listof SSH-Authentication#) (ssh-authentication-methods)] [partial-success? : Boolean #false])]
  [SSH_MSG_USERAUTH_SUCCESS          52 ()]
  [SSH_MSG_USERAUTH_BANNER           53 ([message : String] [language : Symbol '||])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define SSH:USERAUTH:SUCCESS : SSH-MSG-USERAUTH-SUCCESS (make-ssh:msg:userauth:success))
