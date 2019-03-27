#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-8
;;; https://tools.ietf.org/html/rfc4419 [TODO]

(provide (all-defined-out))

(require typed/racket/class)

(require math/base)
(require math/number-theory)

(require "oakley-group.rkt")

(require "../diagnostics.rkt")
(require "../../kex.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-shared-messages diffie-hellman-exchange
  ; https://www.rfc-editor.org/errata_search.php?rfc=4253
  [SSH_MSG_KEXDH_INIT                30 ([e : Integer])]
  [SSH_MSG_KEXDH_REPLY               31 ([K-S : String] [f : Integer] [H : String])])

(define-ssh-shared-messages diffie-hellman-group-exchange
  ; https://tools.ietf.org/html/rfc4419
  [SSH_MSG_KEY_DH_GEX_REQUEST_OLD    30 ([n : Index])]
  [SSH_MSG_KEY_DH_GEX_REQUEST        34 ([min : Index] [n : Index] [max : Index])]
  [SSH_MSG_KEY_DH_GEX_GROUP          31 ([p : Integer] [g : Integer])]
  [SSH_MSG_KEY_DH_GEX_INIT           32 ([e : Integer])]
  [SSH_MSG_KEY_DH_GEX_REPLY          33 ([K-S : String] [f : Integer] [H : String])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#|
 p is a large safe prime
 g is a generator for a subgroup of GF(p)
 q is the order of the subgroup
 V_S is S's identification string
 V_C is C's identification string
 K_S is S's public host key
 I_C is C's SSH_MSG_KEXINIT message
 I_S is S's SSH_MSG_KEXINIT message
|#

(define ssh-diffie-hellman-exchange% : SSH-Key-Exchange<%>
  (class object% (super-new)
    (init Vs Vc Is Ic hostkey hash peer-name)

    (define VIcs : Bytes
      (bytes-append (ssh-string->bytes Vc) (ssh-string->bytes Vs)
                    (ssh-uint32->bytes (bytes-length Ic)) Ic (ssh-uint32->bytes (bytes-length Is)) Is))

    (define/public (tell-message-group)
      'diffie-hellman-exchange)

    (define/public (request)
      (make-ssh:msg:newkeys))

    (define/public (response init-msg)
      (and (ssh:msg:kexdh:init? init-msg)
           (ssh-dh-kex_s dh2048 (ssh:msg:kexdh:init-e init-msg))))

    (define ssh-dh-kex_s : (-> DH-MODP-Group Integer SSH-Message)
      (lambda [dh e]
        (define g : Byte (dh-modp-group-g dh))
        (define p : Integer (dh-modp-group-p dh))
        (define y : Integer (random-integer 2 (dh-modp-group-q dh)))
        (define f : Integer (modular-expt g y p))
        (define K : Integer (modular-expt e y p))
        (define H : Bytes (hash (bytes-append VIcs (ssh-string->bytes hostkey) (ssh-mpint->bytes e) (ssh-mpint->bytes f) (ssh-mpint->bytes K))))
        
        (make-ssh:msg:kexdh:reply #:K-S hostkey #:f f #:H "")))))
