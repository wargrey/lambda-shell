#lang typed/racket/base

(require "../assignment.rkt")
(require "../algorithm/diffie-hellman.rkt")

; datum definition: #(kex-object hash-algorithm)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-algorithms #:kex
  ; http://tools.ietf.org/html/rfc4253#section-8
  ([diffie-hellman-group14-sha1    REQUIRED     #:=> [ssh-diffie-hellman-exchange% sha1-bytes]]
   
   ; https://tools.ietf.org/html/rfc8268#section-3
   [diffie-hellman-group14-sha256  RECOMMENDED]
   [diffie-hellman-group15-sha512  OPTIONAL]
   [diffie-hellman-group16-sha512  OPTIONAL]
   [diffie-hellman-group17-sha512  OPTIONAL]
   [diffie-hellman-group18-sha512  OPTIONAL]))
