#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Message Unsafe-SSH-Bytes->Message)
(provide ssh-message? ssh-message-undefined?)
(provide define-ssh-messages define-ssh-shared-messages)

(provide ssh-message-name
         (rename-out [ssh-message-id ssh-message-number]))

(require "datatype.rkt")
(require "assignment.rkt")

(require "digitama/assignment.rkt")
(require "digitama/message.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-ssh-message-range stx)
  (syntax-case stx [:]
    [(_ type idmin idmax comments ...)
     (with-syntax ([ssh-message? (format-id #'type "ssh-~a-message?" (syntax-e #'type))]
                   [ssh-bytes->range-message (format-id #'type "ssh-bytes->~a-message" (syntax-e #'type))])
       #'(begin (define ssh-message? : (-> SSH-Message Boolean)
                  (lambda [self]
                    (<= idmin (ssh-message-id self) idmax)))
                
                (define ssh-bytes->range-message : (->* (Bytes) (Index #:groups (Listof Symbol)) (Option SSH-Message))
                  (lambda [bmsg [offset 0] #:groups [groups null]]
                    (and (<= idmin (bytes-ref bmsg offset) idmax)
                         (ssh-bytes->message bmsg offset #:groups groups))))))]))

;; https://tools.ietf.org/html/rfc4251#section-7
(define-ssh-message-range transport        1  49   Transport layer protocol)
(define-ssh-message-range authentication  50  79   User authentication protocol)
(define-ssh-message-range connection      80 127   Connection protocol)
(define-ssh-message-range client         128 191   Reserved for client protocols)
(define-ssh-message-range private        192 255   Local extensions for private use)

(define-ssh-message-range generic          1  19   Transport layer generic (e.g., disconnect, ignore, debug, etc.))
(define-ssh-message-range key-exchange    30  49   Key exchange method specific (numbers can be reused for different authentication methods))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://tools.ietf.org/html/rfc4250#section-4.1
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4253
  [SSH_MSG_DISCONNECT                 1 ([reason : (SSH-Symbol SSH-Disconnection-Reason)]
                                         [description : String (symbol->string reason)]
                                         [language : Symbol '||])]
  [SSH_MSG_IGNORE                     2 ([data : String ""])]
  [SSH_MSG_UNIMPLEMENTED              3 ([number : Index])]
  [SSH_MSG_DEBUG                      4 ([display? : Boolean #false] [message : String] [language : Symbol '||])]
  [SSH_MSG_SERVICE_REQUEST            5 ([name : Symbol])]
  [SSH_MSG_SERVICE_ACCEPT             6 ([name : Symbol])]
  [SSH_MSG_KEXINIT                   20 ([cookie : (SSH-Bytes 16) (ssh-cookie)]
                                         [kexes : (SSH-Algorithm-Listof SSH-Kex) (ssh-kex-algorithms)]
                                         [hostkeys : (SSH-Algorithm-Listof SSH-HostKey) (ssh-hostkey-algorithms)]
                                         [c2s-ciphers : (SSH-Algorithm-Listof SSH-Cipher) (ssh-cipher-algorithms)]
                                         [s2c-ciphers : (SSH-Algorithm-Listof SSH-Cipher) (ssh-cipher-algorithms)]
                                         [c2s-macs : (SSH-Algorithm-Listof SSH-HMAC) (ssh-hmac-algorithms)]
                                         [s2c-macs : (SSH-Algorithm-Listof SSH-HMAC) (ssh-hmac-algorithms)]
                                         [c2s-compressions : (SSH-Algorithm-Listof SSH-Compression) (ssh-compression-algorithms)]
                                         [s2c-compressions : (SSH-Algorithm-Listof SSH-Compression) (ssh-compression-algorithms)]
                                         [c2s-languages : (Listof Symbol) null]
                                         [s2c-languages : (Listof Symbol) null]
                                         [guessing-follows? : Boolean #false]
                                         [reserved : Index 0])]
  [SSH_MSG_NEWKEYS                   21 ()]

  ; https://tools.ietf.org/html/rfc8308 
  [SSH_MSG_EXT_INFO                   7 ([nr-extension : Index] [name-value-pair-repetition : Bytes #;[TODO: new feature of parser is required]])]
  [SSH_MSG_NEWCOMPRESS                8 ()])
  
(void #| [30, 49] can be reused for different authentication methods |# 'see "digitama/algorithm/diffie-hellman.rkt")

(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4252
  [SSH_MSG_USERAUTH_REQUEST          50 ([username : Symbol] [service : Symbol] [method : Symbol] [extra : Bytes])]
  [SSH_MSG_USERAUTH_FAILURE          51 ([methods : (Listof Symbol)] [partially? : Boolean])]
  [SSH_MSG_USERAUTH_SUCCESS          52 ()]
  [SSH_MSG_USERAUTH_BANNER           53 ([message : String] [language : Symbol '||])]

  ;; [60, 79] can be reused for different authentication methods
  )

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
(define ssh-message->bytes : (-> SSH-Message Bytes)
  (lambda [self]
    (define name : Symbol (ssh-message-name self))
    (define message->bytes : (Option SSH-Message->Bytes) (hash-ref ssh-message->bytes-database name (λ [] #false)))
    (or (and message->bytes (message->bytes self))

        #|this should not happen|#
        (ssh:msg:ignore->bytes (make-ssh:msg:ignore #:data (format "~s" self))))))

(define ssh-bytes->message : (->* (Bytes) (Index #:groups (Listof Symbol)) SSH-Message)
  (lambda [bmsg [offset 0] #:groups [groups null]]
    (define id : Byte (bytes-ref bmsg offset))
    (define unsafe-bytes->message : (Option Unsafe-SSH-Bytes->Message) (hash-ref ssh-bytes->message-database id (λ [] #false)))
    (or (and unsafe-bytes->message (unsafe-bytes->message bmsg offset))
        (let query : (Option SSH-Message) ([groups : (Listof Symbol) groups])
          (and (pair? groups)
               (let ([bytes->message (ssh-bytes->shared-message (car groups) id)])
                 (or (and bytes->message (bytes->message bmsg offset))
                     (query (cdr groups))))))
        (ssh-undefined-message id))))