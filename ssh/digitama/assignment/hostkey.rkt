#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")
(require "../algorithm/hostkey.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-algorithms #:hostkey
  (; https://tools.ietf.org/html/rfc4251#section-4.1
   ; http://tools.ietf.org/html/rfc4253#section-6.6
   [ssh-dss                        REQUIRED        sign   Raw DSS Key]
   [ssh-rsa                        RECOMMENDED     sign   Raw RSA Key                     #:=> [ssh-rsa% sha1-bytes]]
   [pgp-sign-rsa                   OPTIONAL        sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss                   OPTIONAL        sign   OpenPGP certificates (DSS key)]))
