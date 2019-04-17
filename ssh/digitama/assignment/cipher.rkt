#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253

(require "../assignment.rkt")
(require "../algorithm/crypto/aes.rkt")

; datum definition: #(make-encrypt/decrypt-with-IV-key block-size-in-bytes key-size-in-bytes)

(define-ssh-algorithms #:cipher
  (; http://tools.ietf.org/html/rfc4253#section-6.3
   [3des-cbc                       REQUIRED        three-key 3DES in CBC mode]
   [blowfish-cbc                   OPTIONAL        Blowfish in CBC mode]
   [twofish256-cbc                 OPTIONAL        Twofish in CBC mode with a 256-bit key]
   [twofish-cbc                    OPTIONAL        alias for twofish256-cbc]
   [twofish192-cbc                 OPTIONAL        Twofish with a 192-bit key]
   [twofish128-cbc                 OPTIONAL        Twofish with a 128-bit key]
   [aes256-ctr                     OPTIONAL        AES in CTR mode with a 256-bit key            #:=> [aes-ctr 16 32]]
   [aes192-ctr                     OPTIONAL        AES with a 192-bit key                        #:=> [aes-ctr 16 24]]
   [aes128-ctr                     RECOMMENDED     AES with a 128-bit key                        #:=> [aes-ctr 16 16]]
   [serpent256-cbc                 OPTIONAL        Serpent in CBC mode with a 256-bit key]
   [serpent192-cbc                 OPTIONAL        Serpent with a 192-bit key]
   [serpent128-cbc                 OPTIONAL        Serpent with a 128-bit key]
   [arcfour                        OPTIONAL        the ARCFOUR stream cipher with a 128-bit key]
   [idea-cbc                       OPTIONAL        IDEA in CBC mode]
   [cast128-cbc                    OPTIONAL        CAST-128 in CBC mode]
   [none                           OPTIONAL        no encryption]))
