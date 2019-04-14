#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253

(require "../assignment.rkt")

; datum definition: #(make-encrypt/decrypt-with-IV-key block-size key-size)

(define ssh-cipher-values : (-> Bytes Bytes (Values (-> Bytes Bytes) (-> Bytes Bytes)))
  (lambda [IV key]
    (values values values)))

(define-ssh-algorithms #:cipher
  (; http://tools.ietf.org/html/rfc4253#section-6.3
   [3des-cbc                       REQUIRED        three-key 3DES in CBC mode]
   [blowfish-cbc                   OPTIONAL        Blowfish in CBC mode]
   [twofish256-cbc                 OPTIONAL        Twofish in CBC mode with a 256-bit key]
   [twofish-cbc                    OPTIONAL        alias for twofish256-cbc]
   [twofish192-cbc                 OPTIONAL        Twofish with a 192-bit key]
   [twofish128-cbc                 OPTIONAL        Twofish with a 128-bit key]
   [aes256-cbc                     OPTIONAL        AES in CBC mode with a 256-bit key]
   ;[aes192-cbc                     OPTIONAL        AES with a 192-bit key]
   ;[aes128-cbc                     RECOMMENDED     AES with a 128-bit key]
   [aes192-ctr                     OPTIONAL        AES with a 192-bit key                        #:=> [ssh-cipher-values 0 0]]
   [aes128-ctr                     RECOMMENDED     AES with a 128-bit key                        #:=> [ssh-cipher-values 0 0]]
   [serpent256-cbc                 OPTIONAL        Serpent in CBC mode with a 256-bit key]
   [serpent192-cbc                 OPTIONAL        Serpent with a 192-bit key]
   [serpent128-cbc                 OPTIONAL        Serpent with a 128-bit key]
   [arcfour                        OPTIONAL        the ARCFOUR stream cipher with a 128-bit key]
   [idea-cbc                       OPTIONAL        IDEA in CBC mode]
   [cast128-cbc                    OPTIONAL        CAST-128 in CBC mode]
   [none                           OPTIONAL        no encryption]))
