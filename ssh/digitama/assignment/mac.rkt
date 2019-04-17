#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253
;;; https://tools.ietf.org/html/rfc6668

(require "../assignment.rkt")
(require "../algorithm/hmac.rkt")

; datum definition:  #(make-mac-with-key key-length-in-bytes)

(define-ssh-algorithms #:mac
  (; http://tools.ietf.org/html/rfc4253#section-6.4
   [hmac-sha1         REQUIRED        HMAC-SHA1 (digest length = key length = 20)                      #:=> [hmac-sha1 20]]
   [hmac-sha1-96      RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20) #:=> [hmac-sha1-96 20]]
   [hmac-md5          OPTIONAL        HMAC-MD5 (digest length = key length = 16)]
   [hmac-md5-96       OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)]

   ; http://tools.ietf.org/html/rfc6668#section-2
   [hmac-sha2-256     RECOMMENDED     HMAC-SHA2-256 (digest length = 32 bytes key length = 32 bytes)   #:=> [hmac-sha256 32]]
   [hmac-sha2-512     OPTIONAL        HMAC-SHA2-512 (digest length = 64 bytes key length = 64 bytes)]

   [none              OPTIONAL        no MAC, NOT RECOMMANDED                                          #:=> [hmac-none 0]]))
