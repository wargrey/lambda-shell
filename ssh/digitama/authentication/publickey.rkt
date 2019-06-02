#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "../userauth.rkt")

(require "../message.rkt")
(require "../../message.rkt")
(require "../../datatype.rkt")

; `define-ssh-case-messages` requires this because of Racket phase compilation model
(require (for-syntax "../../message.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; https://tools.ietf.org/html/rfc4252#section-8
(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST
  [PUBLICKEY #:method 'publickey ([adequate? : Boolean #false] [algorithm : String] [key : SSH-BString]) #:case adequate?])

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST-PUBLICKEY
  [($)       #:adequate? '#true ([signature : SSH-BString])])

(define-ssh-shared-messages publickey
  [SSH_MSG_USERAUTH_PK_OK 60 ([algorithm : String] [key : SSH-BString])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-userauth-publickey% : SSH-User-Authentication<%>
  (class object% (super-new)
    (init-field session-id)

    (define/public (tell-method-name)
      'publickey)

    (define/public (request username service response)
      (or response (make-ssh:msg:userauth:request #:username username #:service service #:method 'publickey)))

    (define/public (response request)
      (or (and (ssh:msg:userauth:request:publickey$? request)
               #false)
          (and (ssh:msg:userauth:request:publickey? request)
               (make-ssh:msg:userauth:pk:ok #:algorithm (ssh:msg:userauth:request:publickey-algorithm request)
                                            #:key (ssh:msg:userauth:request:publickey-key request)))))

    (define/public (abort)
      (void))))
