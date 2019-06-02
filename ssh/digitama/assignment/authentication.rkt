#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")
(require "../authentication/publickey.rkt")

; datum definition: userauth%

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-ssh-algorithms #:authentication
  ; https://tools.ietf.org/html/rfc4252#section-5
  ([publickey    REQUIRED        #:=> ssh-userauth-publickey%]
   [password     OPTIONAL]
   [hostbased    OPTIONAL]
   [none         NOT RECOMMANDED]))
