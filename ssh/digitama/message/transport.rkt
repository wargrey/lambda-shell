#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")
(require "../assignment.rkt")
(require "../assignment/disconnection.rkt")

(require "../algorithm/random.rkt")

(require "../../datatype.rkt")

; maessages in [30, 49] can be reused for different key exchange authentication methods
; see 'ssh/digitama/algorithm/kex/diffie-hellman

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
                                         [kexes : (SSH-Name-Listof SSH-Kex#) (ssh-kex-algorithms)]
                                         [hostkeys : (SSH-Name-Listof SSH-Hostkey#) (ssh-hostkey-algorithms)]
                                         [c2s-ciphers : (SSH-Name-Listof SSH-Cipher#) (ssh-cipher-algorithms)]
                                         [s2c-ciphers : (SSH-Name-Listof SSH-Cipher#) (ssh-cipher-algorithms)]
                                         [c2s-macs : (SSH-Name-Listof SSH-MAC#) (ssh-mac-algorithms)]
                                         [s2c-macs : (SSH-Name-Listof SSH-MAC#) (ssh-mac-algorithms)]
                                         [c2s-compressions : (SSH-Name-Listof SSH-Compression#) (ssh-compression-algorithms)]
                                         [s2c-compressions : (SSH-Name-Listof SSH-Compression#) (ssh-compression-algorithms)]
                                         [c2s-languages : (Listof Symbol) null]
                                         [s2c-languages : (Listof Symbol) null]
                                         [guessing-follows? : Boolean #false]
                                         [reserved : Index 0])]
  [SSH_MSG_NEWKEYS                   21 ()]

  ; https://tools.ietf.org/html/rfc8308 
  [SSH_MSG_EXT_INFO                   7 ([nr-extension : Index] [name-value-pair-repetition : Bytes #;[TODO: new feature of parser is required]])]
  [SSH_MSG_NEWCOMPRESS                8 ()])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define SSH:NEWKEYS : SSH-MSG-NEWKEYS (make-ssh:msg:newkeys))
