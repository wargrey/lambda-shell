#lang typed/racket/base

(require "../assignment.rkt")
(require "../algorithm/hostkey/rsa.rkt")
(require "../algorithm/pkcs1/hash.rkt")

; datum definition: #(hostkey-object hash-object)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-algorithms #:hostkey
  (; https://tools.ietf.org/html/rfc4251#section-4.1
   ; http://tools.ietf.org/html/rfc4253#section-6.6
   [ssh-dss          REQUIRED        sign   Raw DSS Key]
   [ssh-rsa          RECOMMENDED     sign   Raw RSA Key                     #:=> [ssh-rsa% pkcs#1-id-sha1]]
   [pgp-sign-rsa     OPTIONAL        sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss     OPTIONAL        sign   OpenPGP certificates (DSS key)]))
