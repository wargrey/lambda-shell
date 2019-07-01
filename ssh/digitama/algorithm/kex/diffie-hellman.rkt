#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-8

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "oakley-group.rkt")

(require "../../diagnostics.rkt")
(require "../../../kex.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-shared-messages diffie-hellman-exchange
  ; https://www.rfc-editor.org/errata_search.php?rfc=4253
  [SSH_MSG_KEXDH_INIT                30 ([e : Integer])]
  [SSH_MSG_KEXDH_REPLY               31 ([K-S : SSH-BString] [f : Integer] [s : SSH-BString])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#|
 p is a large safe prime
 g is the generator for a subgroup of GF(p)
 q is the order of the subgroup
 V_S is S's identification string
 V_C is C's identification string
 K_S is S's public host key
 I_C is C's SSH_MSG_KEXINIT message
 I_S is S's SSH_MSG_KEXINIT message
|#

(struct ssh-diffie-hellman-kex ssh-kex
  ([VIcs : Bytes]
   [dh-group : DH-MODP-Group]
   [x : (Boxof Integer)]
   [e : (Boxof Integer)])
  #:type-name SSH-Diffie-Hellman-Kex)

(define make-ssh-diffie-hellman-exchange : SSH-Kex-Constructor
  (lambda [Vc Vs Ic Is hostkey hash]
    (define VIcs : Bytes
      (bytes-append (ssh-string->bytes Vc) (ssh-string->bytes Vs)
                    (ssh-uint32->bytes (bytes-length Ic)) Ic (ssh-uint32->bytes (bytes-length Is)) Is))

    (ssh-diffie-hellman-kex 'diffie-hellman-exchange hostkey hash
                            ssh-diffie-hellman-exchange-request ssh-diffie-hellman-exchange-reply ssh-diffie-hellman-exchange-verify
                            VIcs dh2048 (box 0) (box 0))))

(define ssh-diffie-hellman-exchange-request : SSH-Kex-Request
  (lambda [self]
    (with-asserts ([self ssh-diffie-hellman-kex?])
      (define dh-group : DH-MODP-Group (ssh-diffie-hellman-kex-dh-group self))
    
      (define g : Byte (dh-modp-group-g dh-group))
      (define p : Integer (dh-modp-group-p dh-group))
      (define x : Integer (dh-random dh-group 1)) ; x <- (1, q)
      (define e : Integer (modular-expt g x p))
      
      (set-box! (ssh-diffie-hellman-kex-x self) x)
      (set-box! (ssh-diffie-hellman-kex-e self) e)
      
      (make-ssh:msg:kexdh:init #:e e))))

(define ssh-diffie-hellman-exchange-reply : SSH-Kex-Reply
  (lambda [self req]
    (with-asserts ([self ssh-diffie-hellman-kex?])
      (and (ssh:msg:kexdh:init? req)
           (let ([dh-group (ssh-diffie-hellman-kex-dh-group self)]
                 [hostkey (ssh-kex-hostkey self)])    
             (define g : Byte (dh-modp-group-g dh-group))
             (define p : Integer (dh-modp-group-p dh-group))
             (define e : Integer (ssh:msg:kexdh:init-e req))
             (define y : Integer (dh-random dh-group 0)) ; y <- (0, q)
             (define f : Integer (modular-expt g y p))
             (define K : Integer (modular-expt e y p))
             (define K-S : Bytes ((ssh-hostkey-make-public-key hostkey) hostkey))
             (define H : Bytes (dh-hash self K-S e f K))
             (define s : Bytes ((ssh-hostkey-sign hostkey) hostkey H))
             
             (when (or (< e 1) (> e (sub1 p)))
               (ssh-raise-kex-error self "'e' is out of range, expected in [1, p-1]"))
             
             (cons (make-ssh:msg:kexdh:reply #:K-S K-S #:f f #:s s)
                   (cons K H)))))))

(define ssh-diffie-hellman-exchange-verify : SSH-Kex-Verify
  (lambda [self reply]
    (with-asserts ([self ssh-diffie-hellman-kex?])
      (and (ssh:msg:kexdh:reply? reply)
           (let ([dh-group (ssh-diffie-hellman-kex-dh-group self)]
                 [hostkey (ssh-kex-hostkey self)])
             (define p : Integer (dh-modp-group-p dh-group))
             (define f : Integer (ssh:msg:kexdh:reply-f reply))
             (define K : Integer (modular-expt f (unbox (ssh-diffie-hellman-kex-x self)) p))
             (define K-S : Bytes (ssh:msg:kexdh:reply-K-S reply))
             (define s : Bytes (ssh:msg:kexdh:reply-s reply))
             (define H : Bytes (dh-hash self K-S (unbox (ssh-diffie-hellman-kex-e self)) f K))
             
             (when (or (< f 1) (> f (sub1 p)))
               (ssh-raise-kex-error self "'f' is out of range, expected in [1, p-1]"))
             
             (unless (bytes=? ((ssh-hostkey-sign hostkey) hostkey H) s)
               (ssh-raise-kex-error #:hostkey? #true
                                    self "Hostkey signature is mismatch"))
             
             (cons K H))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dh-random : (-> DH-MODP-Group Byte Integer)
  (lambda [dh-group open-min]
    (random-integer (add1 open-min)
                    (dh-modp-group-q dh-group))))

(define dh-hash : (-> SSH-Diffie-Hellman-Kex Bytes Integer Integer Integer Bytes)
  (lambda [self K-S e f K]
    ((ssh-kex-hash self)
     (bytes-append (ssh-diffie-hellman-kex-VIcs self)
                   (ssh-uint32->bytes (bytes-length K-S)) K-S
                   (ssh-mpint->bytes e) (ssh-mpint->bytes f) (ssh-mpint->bytes K)))))
