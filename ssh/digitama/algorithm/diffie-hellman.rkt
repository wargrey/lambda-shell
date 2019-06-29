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
  [SSH_MSG_KEXDH_REPLY               31 ([K-S : SSH-BString] [f : Integer] [s : SSH-BString])])

(define-ssh-shared-messages diffie-hellman-group-exchange
  ; https://tools.ietf.org/html/rfc4419
  [SSH_MSG_KEY_DH_GEX_REQUEST_OLD    30 ([n : Index])]
  [SSH_MSG_KEY_DH_GEX_REQUEST        34 ([min : Index] [n : Index] [max : Index])]
  [SSH_MSG_KEY_DH_GEX_GROUP          31 ([p : Integer] [g : Integer])]
  [SSH_MSG_KEY_DH_GEX_INIT           32 ([e : Integer])]
  [SSH_MSG_KEY_DH_GEX_REPLY          33 ([K-S : SSH-BString] [f : Integer] [s : SSH-BString])])

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
    (init Vc Vs Ic Is hostkey hash)

    (define VIcs : Bytes
      (bytes-append (ssh-string->bytes Vc) (ssh-string->bytes Vs)
                    (ssh-uint32->bytes (bytes-length Ic)) Ic (ssh-uint32->bytes (bytes-length Is)) Is))

    (define dh-group : DH-MODP-Group dh2048)
    (define &x : (Boxof Integer) (box 0))
    (define &e : (Boxof Integer) (box 0))
    (define &shared-secret : (Boxof Integer) (box 0))
    (define &exchange-hash : (Boxof Bytes) (box #""))

    (define/public (tell-message-group)
      'diffie-hellman-exchange)

    (define/public (request)
      (define g : Byte (dh-modp-group-g dh-group))
      (define p : Integer (dh-modp-group-p dh-group))
      (define x : Integer (dh-random 1)) ; x <- (1, q)
      (define e : Integer (modular-expt g x p))

      (set-box! &x x)
      (set-box! &e e)
      
      (make-ssh:msg:kexdh:init #:e e))

    (define/public (response req)
      (cond [(ssh:msg:kexdh:init? req) (dh-reply req)]
            [(ssh:msg:kexdh:reply? req) (dh-verify req)]
            [else #false]))

    (define/public (done?)
      (and (> (unbox &shared-secret) 0)
           #;(> (bytes-length (unbox &exchange-hash)) 0)))

    (define/public (tell-secret)
      (values (unbox &shared-secret)
              (unbox &exchange-hash)))

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    (define dh-reply : (-> SSH-MSG-KEXDH-INIT SSH-Message)
      (lambda [req]
        (define g : Byte (dh-modp-group-g dh-group))
        (define p : Integer (dh-modp-group-p dh-group))
        (define e : Integer (ssh:msg:kexdh:init-e req))
        (define y : Integer (dh-random 0)) ; y <- (0, q)
        (define f : Integer (modular-expt g y p))
        (define K : Integer (modular-expt e y p))
        (define K-S : Bytes (send hostkey make-pubkey/certificates))
        (define H : Bytes (dh-hash K-S e f K))
        (define s : Bytes (send hostkey make-signature H))

        (when (or (< e 1) (> e (sub1 p)))
          (ssh-raise-kex-error ssh-diffie-hellman-exchange%
                               "'e' is out of range, expected in [1, p-1]"))

        (set-box! &shared-secret K)
        (set-box! &exchange-hash H)

        (make-ssh:msg:kexdh:reply #:K-S K-S #:f f #:s s)))

    (define dh-verify : (-> SSH-MSG-KEXDH-REPLY SSH-Message)
      (lambda [req]
        (define p : Integer (dh-modp-group-p dh-group))
        (define f : Integer (ssh:msg:kexdh:reply-f req))
        (define K : Integer (modular-expt f (unbox &x) p))
        (define K-S : Bytes (ssh:msg:kexdh:reply-K-S req))
        (define s : Bytes (ssh:msg:kexdh:reply-s req))
        (define H : Bytes (dh-hash K-S (unbox &e) f K))
        
        (when (or (< f 1) (> f (sub1 p)))
          (ssh-raise-kex-error ssh-diffie-hellman-exchange%
                               "'f' is out of range, expected in [1, p-1]"))
        
        (unless (bytes=? (send hostkey make-signature H) s)
          (ssh-raise-kex-error #:hostkey? #true
                               ssh-diffie-hellman-exchange%
                               "Hostkey signature is mismatch"))

        (set-box! &shared-secret K)
        (set-box! &exchange-hash H)

        (make-ssh:msg:newkeys)))

    (define dh-random : (-> Byte Integer)
      (lambda [open-min]
        (random-integer (add1 open-min)
                        (dh-modp-group-q dh-group))))

    (define dh-hash : (-> Bytes Integer Integer Integer Bytes)
      (lambda [K-S e f K]
        (hash (bytes-append VIcs
                            (ssh-uint32->bytes (bytes-length K-S)) K-S
                            (ssh-mpint->bytes e) (ssh-mpint->bytes f) (ssh-mpint->bytes K)))))))
