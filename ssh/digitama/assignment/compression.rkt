#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253

(require "../assignment.rkt")

; datum definition: #(inflate deflate)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-names #:compression
  (; http://tools.ietf.org/html/rfc4253#section-6.2
   [none        REQUIRED        no compression           #:=> [#false #false]]
   [zlib        OPTIONAL        ZLIB (LZ77) compression]))
