#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-assignment stx)
  (syntax-case stx [: quote]
    [(_ id : TypeU [enum0 group0 comments0 ...] [enum group comments ...] ...)
     (with-syntax ([id? (format-id #'id "~a?" (syntax-e #'id))]
                   [id?* (format-id #'id "~a?*" (syntax-e #'id))]
                   [TypeU* (format-id #'TypeU "~a*" (syntax-e #'TypeU))])
     #'(begin (define-type TypeU (U 'enum0 'enum ...))
              (define-type TypeU* (Listof TypeU))
              (define id : (Pairof TypeU TypeU*) (cons 'enum0 (list 'enum ...)))
              (define id? : (-> Any Boolean : TypeU)
                (λ [v] (cond [(eq? v 'enum0) #true] [(eq? v 'enum) #true] ... [else #false])))
              (define id?* : (-> (Listof Any) Boolean : TypeU*)
                (λ [es] ((inst andmap Any Boolean TypeU) id? es)))))]))

(define-assignment ssh-algorithms/cipher : SSH-Algorithm/Cipher
  ; http://tools.ietf.org/html/rfc4253#section-6.3
  [3des-cbc                    REQUIRED          three-key 3DES in CBC mode]
  [blowfish-cbc                OPTIONAL          Blowfish in CBC mode]
  [twofish256-cbc              OPTIONAL          Twofish in CBC mode with a 256-bit key]
  [twofish-cbc                 OPTIONAL          alias for twofish256-cbc]
  [twofish192-cbc              OPTIONAL          Twofish with a 192-bit key]
  [twofish128-cbc              OPTIONAL          Twofish with a 128-bit key]
  [aes256-cbc                  OPTIONAL          AES in CBC mode with a 256-bit key]
  [aes192-cbc                  OPTIONAL          AES with a 192-bit key]
  [aes128-cbc                  RECOMMENDED       AES with a 128-bit key]
  [serpent256-cbc              OPTIONAL          Serpent in CBC mode with a 256-bit key]
  [serpent192-cbc              OPTIONAL          Serpent with a 192-bit key]
  [serpent128-cbc              OPTIONAL          Serpent with a 128-bit key]
  [arcfour                     OPTIONAL          the ARCFOUR stream cipher with a 128-bit key]
  [idea-cbc                    OPTIONAL          IDEA in CBC mode]
  [cast128-cbc                 OPTIONAL          CAST-128 in CBC mode]
  [none                        OPTIONAL          no encryption])

(define-assignment ssh-algorithms/mac : SSH-Algorithm/MAC
  ; http://tools.ietf.org/html/rfc4253#section-6.4
  [hmac-sha1                   REQUIRED        HMAC-SHA1 (digest length = key length = 20)]
  [hmac-sha1-96                RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)]
  [hmac-md5                    OPTIONAL        HMAC-MD5 (digest length = key length = 16)]
  [hmac-md5-96                 OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)]
  [none                        OPTIONAL        no MAC]

  ; http://tools.ietf.org/html/rfc6668#section-2
  [hmac-sha2-256               RECOMMENDED   HMAC-SHA2-256 (digest length = 32 bytes key length = 32 bytes)]
  [hmac-sha2-512               OPTIONAL      HMAC-SHA2-512 (digest length = 64 bytes key length = 64 bytes)])

(define-assignment ssh-algorithms/publickey : SSH-Algorithm/Publickey
  ; http://tools.ietf.org/html/rfc4253#section-6.6
  [ssh-dss                     REQUIRED     sign   Raw DSS Key]
  [ssh-rsa                     RECOMMENDED  sign   Raw RSA Key]
  [pgp-sign-rsa                OPTIONAL     sign   OpenPGP certificates (RSA key)]
  [pgp-sign-dss                OPTIONAL     sign   OpenPGP certificates (DSS key)])

(define-assignment ssh-algorithms/compression : SSH-Algorithm/Compression
  ; http://tools.ietf.org/html/rfc4253#section-6.2
  [none                        REQUIRED           no compression]
  [zlib                        OPTIONAL           ZLIB (LZ77) compression])

(define-assignment ssh-algorithms/kex : SSH-Algorithm/Kex
  ; http://tools.ietf.org/html/rfc4253#section-8
  [diffie-hellman-group1-sha1  REQUIRED]
  [diffie-hellman-group14-sha1 REQUIRED])