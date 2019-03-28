#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Kex SSH-Cipher SSH-HostKey SSH-Compression SSH-HMAC)
(provide ssh-cipher-algorithms ssh-kex-algorithms ssh-hostkey-algorithms ssh-hmac-algorithms ssh-compression-algorithms)
(provide define-ssh-symbols define-ssh-algorithms)

(require "digitama/assignment.rkt")
(require "digitama/algorithm/hmac.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Symbols in [0xFE000000, 0xFFFFFFFF] are left for private use.
(define-ssh-symbols SSH-Disconnection-Reason : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.2.2
  ([SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          1]
   [SSH_DISCONNECT_PROTOCOL_ERROR                       2]
   [SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  3]
   [SSH_DISCONNECT_RESERVED                             4]
   [SSH_DISCONNECT_MAC_ERROR                            5]
   [SSH_DISCONNECT_COMPRESSION_ERROR                    6]
   [SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                7]
   [SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       8]
   [SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              9]
   [SSH_DISCONNECT_CONNECTION_LOST                     10]
   [SSH_DISCONNECT_BY_APPLICATION                      11]
   [SSH_DISCONNECT_TOO_MANY_CONNECTIONS                12]
   [SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              13]
   [SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      14]
   [SSH_DISCONNECT_ILLEGAL_USER_NAME                   15]))

(define-ssh-symbols SSH-Channel-Failure-Reason : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.3
  ([SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1]
   [SSH_OPEN_CONNECT_FAILED                             2]
   [SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3]
   [SSH_OPEN_RESOURCE_SHORTAGE                          4]))

(define-ssh-symbols SSH-Channel-Data-Type : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.4
  ([SSH_EXTENDED_DATA_STDERR                            1]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
   [aes192-ctr                     OPTIONAL        AES with a 192-bit key                                           #:=> values]
   [aes128-ctr                     RECOMMENDED     AES with a 128-bit key                                           #:=> values]
   [serpent256-cbc                 OPTIONAL        Serpent in CBC mode with a 256-bit key]
   [serpent192-cbc                 OPTIONAL        Serpent with a 192-bit key]
   [serpent128-cbc                 OPTIONAL        Serpent with a 128-bit key]
   [arcfour                        OPTIONAL        the ARCFOUR stream cipher with a 128-bit key]
   [idea-cbc                       OPTIONAL        IDEA in CBC mode]
   [cast128-cbc                    OPTIONAL        CAST-128 in CBC mode]
   [none                           OPTIONAL        no encryption]))

(define-ssh-algorithms #:hmac
  (; http://tools.ietf.org/html/rfc6668#section-2
   [hmac-sha2-256                  RECOMMENDED     HMAC-SHA2-256 (digest length = 32 bytes key length = 32 bytes)   #:=> [ssh-hmac-sha256 32]]
   [hmac-sha2-512                  OPTIONAL        HMAC-SHA2-512 (digest length = 64 bytes key length = 64 bytes)]

   ; http://tools.ietf.org/html/rfc4253#section-6.4
   [hmac-sha1                      REQUIRED        HMAC-SHA1 (digest length = key length = 20)                      #:=> [ssh-hmac-sha1 20]]
   [hmac-sha1-96                   RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20) #:=> [ssh-hmac-sha1-96 12]]
   [hmac-md5                       OPTIONAL        HMAC-MD5 (digest length = key length = 16)]
   [hmac-md5-96                    OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)]
   
   [none                           OPTIONAL        no MAC, NOT RECOMMANDED                                          #:=> [ssh-hmac-none 0]]))

(define-ssh-algorithms #:hostkey
  (; https://tools.ietf.org/html/rfc4251#section-4.1
   ; http://tools.ietf.org/html/rfc4253#section-6.6
   [ssh-dss                        REQUIRED        sign   Raw DSS Key]
   [ssh-rsa                        RECOMMENDED     sign   Raw RSA Key                                               #:=> values]
   [pgp-sign-rsa                   OPTIONAL        sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss                   OPTIONAL        sign   OpenPGP certificates (DSS key)]))

(define-ssh-algorithms #:compression
  (; http://tools.ietf.org/html/rfc4253#section-6.2
   [none                           REQUIRED        no compression                                                   #:=> values]
   [zlib                           OPTIONAL        ZLIB (LZ77) compression]))
