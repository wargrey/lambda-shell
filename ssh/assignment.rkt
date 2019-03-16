#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "digitama/datatype.rkt"))
(provide (struct-out SSH-Message))
(provide define-ssh-symbols define-ssh-names)

(require "digitama/assignment.rkt")
(require "digitama/datatype.rkt")

(require (for-syntax racket/base))

(define-syntax (define-ssh-messages stx)
  (syntax-case stx [: of]
    [(_ [enum val ([field : FieldType defval ...] ...)] ...)
     #'(begin (define-message enum val ([field : FieldType defval ...] ...)) ...)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://tools.ietf.org/html/rfc4250#section-4.1
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4253
  [SSH_MSG_DISCONNECT                 1 ([reason : (SSH-Symbol SSH-Disconnection-Reason)] [description : String (symbol->string reason)] [language : Symbol '||])]
  [SSH_MSG_IGNORE                     2 ([data : String])]
  [SSH_MSG_UNIMPLEMENTED              3 ([number : Index])]
  [SSH_MSG_DEBUG                      4 ([display? : Boolean #false] [message : String] [language : Symbol '||])]
  [SSH_MSG_SERVICE_REQUEST            5 ([name : Symbol])]
  [SSH_MSG_SERVICE_ACCEPT             6 ([name : Symbol])]
  [SSH_MSG_KEXINIT                   20 ([cookie : (SSH-Bytes 16) (ssh-cookie)]
                                         [kex : (SSH-Namelist SSH-Kex-Method) ssh-kex-method-list]
                                         [publickey : (SSH-Namelist SSH-Publickey-Format) ssh-publickey-format-list]
                                         [local-cipher : (SSH-Namelist SSH-Cipher) ssh-cipher-list]
                                         [remote-cipher : (SSH-Namelist SSH-Cipher) ssh-cipher-list]
                                         [local-mac : (SSH-Namelist SSH-MAC-Algorithm) ssh-mac-algorithm-list]
                                         [remote-mac : (SSH-Namelist SSH-MAC-Algorithm) ssh-mac-algorithm-list]
                                         [local-compression : (SSH-Namelist SSH-Compression-Method) ssh-compression-method-list]
                                         [remote-compression : (SSH-Namelist SSH-Compression-Method) ssh-compression-method-list]
                                         [local-language : (Listof Symbol) null]
                                         [remote-language : (Listof Symbol) null]
                                         [guessing-follow? : Boolean #false]
                                         [reserved : Index 0])]
  [SSH_MSG_NEWKEYS                   21 ()]
  
  ; for http://tools.ietf.org/html/rfc4252
  [SSH_MSG_USERAUTH_REQUEST          50 ([username : Symbol] [service : Symbol] [method : Symbol] [extra : Bytes])]
  [SSH_MSG_USERAUTH_FAILURE          51 ([methods : (Listof Symbol)] [partially? : Boolean])]
  [SSH_MSG_USERAUTH_SUCCESS          52 ()]
  [SSH_MSG_USERAUTH_BANNER           53 ([message : String] [language : Symbol '||])]
  
  ; for http://tools.ietf.org/html/rfc4254
  [SSH_MSG_GLOBAL_REQUEST            80 ([name : Index] [replay? : Boolean] [extra : Bytes])]
  [SSH_MSG_REQUEST_SUCCESS           81 ([extra : Bytes])]
  [SSH_MSG_REQUEST_FAILURE           82 ()]
  [SSH_MSG_CHANNEL_OPEN              90 ([type : Symbol] [partner : Index] [window-size : Index] [packet-upsize : Index] [extra : Bytes])]
  [SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91 ([channel : Index] [partner : Index] [window-size : Index] [packet-upsize : Index] [extra : Bytes])]
  [SSH_MSG_CHANNEL_OPEN_FAILURE      92 ([channel : Index] [reason : (SSH-Symbol SSH-Channel-Failure-Reason)] [descripion : String (symbol->string reason)] [language : Symbol '||])]
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
(define-ssh-names ssh-cipher : SSH-Cipher
  ; http://tools.ietf.org/html/rfc4253#section-6.3
  ([3des-cbc                    REQUIRED          three-key 3DES in CBC mode]
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
   [none                        OPTIONAL          no encryption]))

(define-ssh-names ssh-mac-algorithm : SSH-MAC-Algorithm
  ; http://tools.ietf.org/html/rfc4253#section-6.4
  ([hmac-sha1                   REQUIRED        HMAC-SHA1 (digest length = key length = 20)]
   [hmac-sha1-96                RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)]
   [hmac-md5                    OPTIONAL        HMAC-MD5 (digest length = key length = 16)]
   [hmac-md5-96                 OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)]
   [none                        OPTIONAL        no MAC]
   
  ; http://tools.ietf.org/html/rfc6668#section-2
   [hmac-sha2-256               RECOMMENDED   HMAC-SHA2-256 (digest length = 32 bytes key length = 32 bytes)]
   [hmac-sha2-512               OPTIONAL      HMAC-SHA2-512 (digest length = 64 bytes key length = 64 bytes)]))

(define-ssh-names ssh-publickey-format : SSH-Publickey-Format
  ; http://tools.ietf.org/html/rfc4253#section-6.6
  ([ssh-dss                     REQUIRED     sign   Raw DSS Key]
   [ssh-rsa                     RECOMMENDED  sign   Raw RSA Key]
   [pgp-sign-rsa                OPTIONAL     sign   OpenPGP certificates (RSA key)]
   [pgp-sign-dss                OPTIONAL     sign   OpenPGP certificates (DSS key)]))

(define-ssh-names ssh-compression-method : SSH-Compression-Method
  ; http://tools.ietf.org/html/rfc4253#section-6.2
  ([none                        REQUIRED           no compression]
   [zlib                        OPTIONAL           ZLIB (LZ77) compression]))

(define-ssh-names ssh-kex-method : SSH-Kex-Method
  ; http://tools.ietf.org/html/rfc4253#section-8
  ([diffie-hellman-group1-sha1  REQUIRED]
   [diffie-hellman-group14-sha1 REQUIRED]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-message-number : (-> SSH-Message Byte)
  (lambda [self]
    (SSH-Message-id self)))

(define ssh-message-name : (-> SSH-Message Symbol)
  (lambda [self]
    (hash-ref ssh-message-name-database (SSH-Message-id self)
              (λ [] (assert (object-name struct:SSH-Message) symbol?)))))

(define ssh-bytes->message : (->* (Bytes) (Index) SSH-Message)
  (lambda [bmsg [offset 0]]
    (define id : Byte (bytes-ref bmsg offset))
    (define unsafe-bytes->message : (Option Unsafe-SSH-Bytes->Message) (hash-ref ssh-bytes->message-database id (λ [] #false)))
    (cond [(not unsafe-bytes->message) (make-ssh:msg:unimplemented #:number id)]
          [else (unsafe-bytes->message bmsg offset)])))

(define ssh-message->bytes : (-> SSH-Message Bytes)
  (lambda [self]
    (define id : Byte (SSH-Message-id self))
    (define message->bytes : (Option SSH-Message->Bytes) (hash-ref ssh-message->bytes-database id (λ [] #false)))
    (or (and message->bytes (message->bytes self))

         #|this should not happen|#
         (ssh:msg:ignore->bytes (make-ssh:msg:ignore #:data (format "~s" self))))))
