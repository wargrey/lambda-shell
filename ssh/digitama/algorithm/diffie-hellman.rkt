#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-8
;;; https://tools.ietf.org/html/rfc4419 [TODO]

(provide (all-defined-out))

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

    (ssh-diffie-hellman-kex 'diffie-hellman-exchange hostkey hash (box 0) (box #"")
                            ssh-diffie-hellman-exchange-request ssh-diffie-hellman-exchange-response ssh-diffie-hellman-exchange-done?
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

(define ssh-diffie-hellman-exchange-response : SSH-Kex-Response
  (lambda [self req]
    (with-asserts ([self ssh-diffie-hellman-kex?])
      (cond [(ssh:msg:kexdh:init? req) (dh-reply self req)]
            [(ssh:msg:kexdh:reply? req) (dh-verify self req)]
            [else #false]))))

(define ssh-diffie-hellman-exchange-done? : SSH-Kex-Done?
  (lambda [self]
    (and (> (unbox (ssh-kex-K self)) 0)
         #;(> (bytes-length (unbox (ssh-kex-H self))) 0))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dh-reply : (-> SSH-Diffie-Hellman-Kex SSH-MSG-KEXDH-INIT SSH-Message)
  (lambda [self req]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))
    (define dh-group : DH-MODP-Group (ssh-diffie-hellman-kex-dh-group self))
    
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
    
    (set-box! (ssh-kex-K self) K)
    (set-box! (ssh-kex-H self) H)
    
    (make-ssh:msg:kexdh:reply #:K-S K-S #:f f #:s s)))

(define dh-verify : (-> SSH-Diffie-Hellman-Kex SSH-MSG-KEXDH-REPLY SSH-Message)
  (lambda [self req]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))
    (define dh-group : DH-MODP-Group (ssh-diffie-hellman-kex-dh-group self))

    (define p : Integer (dh-modp-group-p dh-group))
    (define f : Integer (ssh:msg:kexdh:reply-f req))
    (define K : Integer (modular-expt f (unbox (ssh-diffie-hellman-kex-x self)) p))
    (define K-S : Bytes (ssh:msg:kexdh:reply-K-S req))
    (define s : Bytes (ssh:msg:kexdh:reply-s req))
    (define H : Bytes (dh-hash self K-S (unbox (ssh-diffie-hellman-kex-e self)) f K))
    
    (when (or (< f 1) (> f (sub1 p)))
      (ssh-raise-kex-error self "'f' is out of range, expected in [1, p-1]"))
    
    (unless (bytes=? ((ssh-hostkey-sign hostkey) hostkey H) s)
      (ssh-raise-kex-error #:hostkey? #true
                           self "Hostkey signature is mismatch"))
    
    (set-box! (ssh-kex-K self) K)
    (set-box! (ssh-kex-H self) H)
    
    (make-ssh:msg:newkeys)))

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
