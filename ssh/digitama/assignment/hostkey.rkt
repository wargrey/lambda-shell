#lang typed/racket/base

(require "../assignment.rkt")
(require "../algorithm/hostkey/rsa.rkt")
(require "../algorithm/pkcs1/hash.rkt")

; datum definition: #(hostkey-constructor hash-object)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-names #:hostkey
  (; https://tools.ietf.org/html/rfc4251#section-4.1
   ; http://tools.ietf.org/html/rfc4253#section-6.6
   [ssh-dss          REQUIRED        sign   Raw DSS Key]
   [ssh-rsa          RECOMMENDED     sign   Raw RSA Key                     #:=> [make-ssh-rsa-hostkey pkcs#1-id-sha1]]
   [pgp-sign-rsa     OPTIONAL        sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss     OPTIONAL        sign   OpenPGP certificates (DSS key)]

   ; https://tools.ietf.org/html/rfc8332#section-3
   [rsa-sha2-256     RECOMMENDED     sign   Raw RSA Key                     #:=> [make-ssh-rsa-hostkey pkcs#1-id-sha256]]))
