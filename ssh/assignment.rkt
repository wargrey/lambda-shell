#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Message SSH-HMAC)
(provide ssh-hmac-algorithms)
(provide define-ssh-symbols)

(require "digitama/assignment.rkt")
(require "digitama/datatype.rkt")

(require (for-syntax racket/base))

(define-syntax (define-ssh-messages stx)
  (syntax-case stx [: of]
    [(_ [enum val ([field : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val ([field : FieldType defval ...] ...)) ...)]))

(define-syntax (define-ssh-algorithms stx)
  (syntax-case stx [:]
    [(_ #:kex (definition ...))
     #'(begin (define-ssh-algorithm &ssh-kex-algorithms (definition)) ...)]
    [(_ #:hostkey (definition ...))
     #'(begin (define-ssh-algorithm &ssh-hostkey-algorithms (definition)) ...)]
    [(_ #:cipher (definition ...))
     #'(begin (define-ssh-algorithm &ssh-cipher-algorithms (definition)) ...)]
    [(_ #:hmac (definition ...))
     #'(begin (define-ssh-algorithm &ssh-hmac-algorithms (definition)) ...)]
    [(_ #:compression (definition ...))
     #'(begin (define-ssh-algorithm &ssh-compression-algorithms (definition)) ...)]
    [(_ keyword (definitions ...)) (raise-syntax-error 'define-ssh-algorithm "unknonw algorithm type, expected #:hmac, #:cipher, or #:compression" #'keyword)]))

;; https://tools.ietf.org/html/rfc4251#section-7
(define ssh-msg-range/all : (Pairof Byte Byte) (cons 1 255))
(define ssh-msg-range/transport : (Pairof Byte Byte) (cons 1 49))
(define ssh-msg-range/authentication : (Pairof Byte Byte) (cons 50 79))
(define ssh-msg-range/connection : (Pairof Byte Byte) (cons 80 127))
(define ssh-msg-range/client : (Pairof Byte Byte) (cons 128 191))
(define ssh-msg-range/extension : (Pairof Byte Byte) (cons 192 255))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://tools.ietf.org/html/rfc4250#section-4.1
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4253
  [SSH_MSG_DISCONNECT                 1 ([reason : (SSH-Symbol SSH-Disconnection-Reason)]
                                         [description : String (symbol->string reason)]
                                         [language : Symbol '||])]
  [SSH_MSG_IGNORE                     2 ([data : String])]
  [SSH_MSG_UNIMPLEMENTED              3 ([number : Index])]
  [SSH_MSG_DEBUG                      4 ([display? : Boolean #false] [message : String] [language : Symbol '||])]
  [SSH_MSG_SERVICE_REQUEST            5 ([name : Symbol])]
  [SSH_MSG_SERVICE_ACCEPT             6 ([name : Symbol])]
  [SSH_MSG_KEXINIT                   20 ([cookie : (SSH-Bytes 16) (ssh-cookie)]
                                         [kex-methods : (SSH-Algorithm-Listof SSH-Kex) (ssh-kex-algorithms)]
                                         [key-formats : (SSH-Algorithm-Listof SSH-HostKey) (ssh-hostkey-algorithms)]
                                         [c2s-ciphers : (SSH-Algorithm-Listof SSH-Cipher) (ssh-cipher-algorithms)]
                                         [s2c-ciphers : (SSH-Algorithm-Listof SSH-Cipher) (ssh-cipher-algorithms)]
                                         [c2s-mac-algorithms : (SSH-Algorithm-Listof SSH-HMAC) (ssh-hmac-algorithms)]
                                         [s2c-mac-algorithms : (SSH-Algorithm-Listof SSH-HMAC) (ssh-hmac-algorithms)]
                                         [c2s-compression-methods : (SSH-Algorithm-Listof SSH-Compression) (ssh-compression-algorithms)]
                                         [s2c-compression-methods : (SSH-Algorithm-Listof SSH-Compression) (ssh-compression-algorithms)]
                                         [c2s-languages : (Listof Symbol) null]
                                         [s2c-languages : (Listof Symbol) null]
                                         [guessing-follows? : Boolean #false]
                                         [reserved : Index 0])]
  [SSH_MSG_NEWKEYS                   21 ()]

  ; https://www.rfc-editor.org/errata_search.php?rfc=4253
  [SSH_MSG_KEXDH_INIT                30 ([e : Integer])]
  [SSH_MSG_KEXDH_REPLY               31 ([K-S : String] [f : Integer] [H : String])]

  ; https://tools.ietf.org/html/rfc8308 
  [SSH_MSG_EXT_INFO                   7 ([nr-extension : Index] [name-value-pair-repetition : Bytes #;[TODO: new feature of parser is required]])]
  [SSH_MSG_NEWCOMPRESS                8 ()])

(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4252
  [SSH_MSG_USERAUTH_REQUEST          50 ([username : Symbol] [service : Symbol] [method : Symbol] [extra : Bytes])]
  [SSH_MSG_USERAUTH_FAILURE          51 ([methods : (Listof Symbol)] [partially? : Boolean])]
  [SSH_MSG_USERAUTH_SUCCESS          52 ()]
  [SSH_MSG_USERAUTH_BANNER           53 ([message : String] [language : Symbol '||])])

(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4254
  [SSH_MSG_GLOBAL_REQUEST            80 ([name : Index] [replay? : Boolean] [extra : Bytes])]
  [SSH_MSG_REQUEST_SUCCESS           81 ([extra : Bytes])]
  [SSH_MSG_REQUEST_FAILURE           82 ()]
  [SSH_MSG_CHANNEL_OPEN              90 ([type : Symbol] [partner : Index] [window-size : Index] [packet-upsize : Index] [extra : Bytes])]
  [SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91 ([channel : Index] [partner : Index] [window-size : Index] [packet-upsize : Index] [extra : Bytes])]
  [SSH_MSG_CHANNEL_OPEN_FAILURE      92 ([channel : Index]
                                         [reason : (SSH-Symbol SSH-Channel-Failure-Reason)]
                                         [descripion : String (symbol->string reason)]
                                         [language : Symbol '||])]
  [SSH_MSG_CHANNEL_WINDOW_ADJUST     93 ([channel : Index] [size : Index])]
  [SSH_MSG_CHANNEL_DATA              94 ([channel : Index] [data : String])]
  [SSH_MSG_CHANNEL_EXTENDED_DATA     95 ([channel : Index] [type : (SSH-Symbol SSH-Channel-Data-Type)] [data : String])]
  [SSH_MSG_CHANNEL_EOF               96 ([channel : Index])]
  [SSH_MSG_CHANNEL_CLOSE             97 ([channel : Index])]
  [SSH_MSG_CHANNEL_REQUEST           98 ([channel : Index] [type : Symbol] [reply? : Boolean] [extra : Bytes])]
  [SSH_MSG_CHANNEL_SUCCESS           99 ([channel : Index])]
  [SSH_MSG_CHANNEL_FAILURE          100 ([channel : Index])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
  ; http://tools.ietf.org/html/rfc4253#section-6.3
  ([3des-cbc                       REQUIRED        three-key 3DES in CBC mode]
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
  ; http://tools.ietf.org/html/rfc4253#section-6.4
  ([hmac-sha1                      REQUIRED        HMAC-SHA1 (digest length = key length = 20)                      #:=> sha1-bytes]
   [hmac-sha1-96                   RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)]
   [hmac-md5                       OPTIONAL        HMAC-MD5 (digest length = key length = 16)]
   [hmac-md5-96                    OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)]
   
   ; http://tools.ietf.org/html/rfc6668#section-2
   [hmac-sha2-256                  RECOMMENDED     HMAC-SHA2-256 (digest length = 32 bytes key length = 32 bytes)   #:=> sha256-bytes]
   [hmac-sha2-512                  OPTIONAL        HMAC-SHA2-512 (digest length = 64 bytes key length = 64 bytes)]

   [none                           OPTIONAL        no MAC, NOT RECOMMANDED                                          #:=> ssh-hmac-none-bytes]))

(define-ssh-algorithms #:hostkey
  ; http://tools.ietf.org/html/rfc4253#section-6.6
  ([ssh-dss                        REQUIRED        sign   Raw DSS Key]
   [ssh-rsa                        RECOMMENDED     sign   Raw RSA Key                                               #:=> values]
   [pgp-sign-rsa                   OPTIONAL        sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss                   OPTIONAL        sign   OpenPGP certificates (DSS key)]))

(define-ssh-algorithms #:compression
  ; http://tools.ietf.org/html/rfc4253#section-6.2
  ([none                           REQUIRED        no compression                                                   #:=> values]
   [zlib                           OPTIONAL        ZLIB (LZ77) compression]))

(define-ssh-algorithms #:kex
  ; http://tools.ietf.org/html/rfc4253#section-8
  ([diffie-hellman-group14-sha1    REQUIRED                                                                         #:=> values]

   ; https://tools.ietf.org/html/rfc8268#section-3
   [diffie-hellman-group14-sha256  RECOMMENDED]
   [diffie-hellman-group15-sha512  OPTIONAL]
   [diffie-hellman-group16-sha512  OPTIONAL]
   [diffie-hellman-group17-sha512  OPTIONAL]
   [diffie-hellman-group18-sha512  OPTIONAL]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-message-number : (-> SSH-Message Byte)
  (lambda [self]
    (SSH-Message-id self)))

(define ssh-message-name : (-> SSH-Message Symbol)
  (lambda [self]
    (or (ssh-message-number->name (SSH-Message-id self))
        (assert (object-name struct:SSH-Message) symbol?))))

(define ssh-message->bytes : (-> SSH-Message Bytes)
  (lambda [self]
    (define id : Byte (SSH-Message-id self))
    (define message->bytes : (Option SSH-Message->Bytes) (hash-ref ssh-message->bytes-database id (λ [] #false)))
    (or (and message->bytes (message->bytes self))

         #|this should not happen|#
         (ssh:msg:ignore->bytes (make-ssh:msg:ignore #:data (format "~s" self))))))

(define ssh-bytes->message : (->* (Bytes) (Index) SSH-Message)
  (lambda [bmsg [offset 0]]
    (define id : Byte (bytes-ref bmsg offset))
    (define unsafe-bytes->message : (Option Unsafe-SSH-Bytes->Message) (hash-ref ssh-bytes->message-database id (λ [] #false)))
    (cond [(not unsafe-bytes->message) (make-ssh:msg:unimplemented #:number id)]
          [else (unsafe-bytes->message bmsg offset)])))

(define ssh-bytes->message* : (->* (Bytes (Pairof Byte Byte)) (Index) (Option SSH-Message))
  (lambda [bmsg range [offset 0]]
    (and (<= (car range) (bytes-ref bmsg offset) (cdr range))
         (ssh-bytes->message bmsg offset))))
