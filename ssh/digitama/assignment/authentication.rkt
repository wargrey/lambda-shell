#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")
(require "../authentication/publickey.rkt")

; datum definition: userauth-constructor

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-algorithms #:authentication
  ; https://tools.ietf.org/html/rfc4252#section-5
  ([publickey    REQUIRED        #:=> make-ssh-publickey-userauth]
   [password     OPTIONAL]
   [hostbased    OPTIONAL]
   [none         NOT RECOMMANDED]))
