#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4419

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "oakley-group.rkt")

(require "../../diagnostics.rkt")
(require "../../../kex.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-shared-messages diffie-hellman-group-exchange
  ; https://tools.ietf.org/html/rfc4419
  [SSH_MSG_KEX_DH_GEX_REQUEST_OLD    30 ([n : Index])]
  [SSH_MSG_KEX_DH_GEX_REQUEST        34 ([min : Index] [n : Index] [max : Index])]
  [SSH_MSG_KEX_DH_GEX_GROUP          31 ([p : Integer] [g : Integer])]
  [SSH_MSG_KEX_DH_GEX_INIT           32 ([e : Integer])]
  [SSH_MSG_KEX_DH_GEX_REPLY          33 ([K-S : SSH-BString] [f : Integer] [s : SSH-BString])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#|
 p is a large safe prime
 g is the generator for a subgroup of GF(p)
 e is C's exchange value
 f is S's exchange value
 K is the shared secret
 V_S is S's identification string
 V_C is C's identification string
 K_S is S's public host key
 I_C is C's SSH_MSG_KEXINIT message
 I_S is S's SSH_MSG_KEXINIT message
|#

(struct ssh-diffie-hellman-group-kex ssh-kex
  ([VIcs : Bytes]
   [bits-range : (Boxof (Listof Index))]
   [p : (Boxof Integer)]
   [g : (Boxof Integer)]
   [x : (Boxof Integer)]
   [e : (Boxof Integer)])
  #:type-name SSH-Diffie-Hellman-Group-Kex)

(define make-ssh-diffie-hellman-group-exchange : SSH-Kex-Constructor
  (lambda [Vc Vs Ic Is hostkey hash]
    (define VIcs : Bytes
      (bytes-append (ssh-string->bytes Vc) (ssh-string->bytes Vs)
                    (ssh-uint32->bytes (bytes-length Ic)) Ic (ssh-uint32->bytes (bytes-length Is)) Is))

    (ssh-diffie-hellman-group-kex 'diffie-hellman-group-exchange hostkey hash
                                  ssh-diffie-hellman-group-exchange-request ssh-diffie-hellman-group-exchange-reply ssh-diffie-hellman-group-exchange-verify
                                  VIcs (box null) (box 0) (box 0) (box 0) (box 0))))

(define ssh-diffie-hellman-group-exchange-request : SSH-Kex-Request
  (lambda [self]
    (with-asserts ([self ssh-diffie-hellman-group-kex?])
      (define all-prime-sizes : (Listof Index) (sort (hash-keys dh-modp-groups) <))
      (define minbits : Index (car all-prime-sizes))
      (define maxbits : Index (car (reverse all-prime-sizes)))
      (define nbits : Index (max minbits 3702))

      (set-box! (ssh-diffie-hellman-group-kex-bits-range self) (list minbits nbits maxbits))
      
      (make-ssh:msg:kex:dh:gex:request #:min minbits #:n nbits #:max maxbits))))

(define ssh-diffie-hellman-group-exchange-reply : SSH-Kex-Reply
  (lambda [self req]
    (with-asserts ([self ssh-diffie-hellman-group-kex?])
      (cond [(ssh:msg:kex:dh:gex:request:old? req) (dhg-request self req)]
            [(ssh:msg:kex:dh:gex:request? req) (dhg-request self req)]
            [(ssh:msg:kex:dh:gex:init? req) (dhg-reply self req)]
            [else #false]))))

(define ssh-diffie-hellman-group-exchange-verify : SSH-Kex-Verify
  (lambda [self reply]
    (with-asserts ([self ssh-diffie-hellman-group-kex?])
      (cond [(ssh:msg:kex:dh:gex:group? reply) (dhg-init self reply)]
            [(ssh:msg:kex:dh:gex:reply? reply) (dhg-verify self reply)]
            [else #false]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dhg-request : (-> SSH-Diffie-Hellman-Group-Kex (U SSH-MSG-KEX-DH-GEX-REQUEST-OLD SSH-MSG-KEX-DH-GEX-REQUEST) SSH-Message)
  (lambda [self req]
    (define-values (dh-group bits-range)
      (cond [(ssh:msg:kex:dh:gex:request:old? req) (dhg-seek (ssh:msg:kex:dh:gex:request:old-n req))]
            [else (dhg-seek (ssh:msg:kex:dh:gex:request-min req) (ssh:msg:kex:dh:gex:request-n req) (ssh:msg:kex:dh:gex:request-max req))]))

    (set-box! (ssh-diffie-hellman-group-kex-bits-range self) bits-range)
    (set-box! (ssh-diffie-hellman-group-kex-p self) (dh-modp-group-p dh-group))
    (set-box! (ssh-diffie-hellman-group-kex-g self) (dh-modp-group-g dh-group))
    
    (make-ssh:msg:kex:dh:gex:group #:p (dh-modp-group-p dh-group) #:g (dh-modp-group-g dh-group))))

(define dhg-init : (-> SSH-Diffie-Hellman-Group-Kex SSH-MSG-KEX-DH-GEX-GROUP SSH-Message)
  (lambda [self req]
    (define p : Integer (ssh:msg:kex:dh:gex:group-p req))
    (define g : Integer (ssh:msg:kex:dh:gex:group-g req))
    (define x : Integer (dhg-random p 1)) ; x <- (1, q)
    (define e : Integer (modular-expt g x p))

    (set-box! (ssh-diffie-hellman-group-kex-p self) p)
    (set-box! (ssh-diffie-hellman-group-kex-g self) g)
    (set-box! (ssh-diffie-hellman-group-kex-x self) x)
    (set-box! (ssh-diffie-hellman-group-kex-e self) e)
    
    (make-ssh:msg:kex:dh:gex:init #:e e)))

(define dhg-reply : (-> SSH-Diffie-Hellman-Group-Kex SSH-MSG-KEX-DH-GEX-INIT (Pairof SSH-Message (Pairof Integer Bytes)))
  (lambda [self req]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))

    (define g : Integer (unbox (ssh-diffie-hellman-group-kex-g self)))
    (define p : Integer (unbox (ssh-diffie-hellman-group-kex-p self)))
    (define e : Integer (ssh:msg:kex:dh:gex:init-e req))
    (define y : Integer (dhg-random p 0)) ; y <- (0, q)
    (define f : Integer (modular-expt g y p))
    (define K : Integer (modular-expt e y p))
    (define K-S : Bytes ((ssh-hostkey-make-public-key hostkey) hostkey))
    (define H : Bytes (dhg-hash self K-S e f K))
    (define s : Bytes ((ssh-hostkey-sign hostkey) hostkey H))
    
    (when (or (< e 1) (> e (sub1 p)))
      (ssh-raise-kex-error self "'e' is out of range, expected in [1, p-1]"))
    
    (cons (make-ssh:msg:kex:dh:gex:reply #:K-S K-S #:f f #:s s)
          (cons K H))))

(define dhg-verify : (-> SSH-Diffie-Hellman-Group-Kex SSH-MSG-KEX-DH-GEX-REPLY (Pairof Integer Bytes))
  (lambda [self reply]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))

    (define p : Integer (unbox (ssh-diffie-hellman-group-kex-p self)))
    (define x : Integer (unbox (ssh-diffie-hellman-group-kex-x self)))
    (define e : Integer (unbox (ssh-diffie-hellman-group-kex-e self)))
    (define f : Integer (ssh:msg:kex:dh:gex:reply-f reply))
    (define K : Integer (modular-expt f x p))
    (define K-S : Bytes (ssh:msg:kex:dh:gex:reply-K-S reply))
    (define s : Bytes (ssh:msg:kex:dh:gex:reply-s reply))
    (define H : Bytes (dhg-hash self K-S e f K))
    
    (when (or (< f 1) (> f (sub1 p)))
      (ssh-raise-kex-error self "'f' is out of range, expected in [1, p-1]"))
    
    (unless (bytes=? ((ssh-hostkey-sign hostkey) hostkey H) s)
      (ssh-raise-kex-error #:hostkey? #true
                           self "Hostkey signature is mismatch"))
    
    (cons K H)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dhg-seek : (case-> [Index -> (Values DH-MODP-Group (Listof Index))]
                           [Index Index Index -> (Values DH-MODP-Group (Listof Index))])
  (case-lambda
    [(n)
     (values (hash-ref dh-modp-groups n (λ [] (ssh-raise-kex-error dhg-request "unable to find the ~a-bits-sized prime" n)))
             (list n))]
    [(min n max)
     (cond [(not (<= min n max)) (ssh-raise-kex-error dhg-request "invalid prime size range: ~a <= ~a <= ~a" min n max)]
           [else (values (hash-ref dh-modp-groups min
                                   (λ [] (let seek : DH-MODP-Group ([nbits : (Listof Index) (sort (hash-keys dh-modp-groups) <)])
                                           (cond [(null? nbits) (ssh-raise-kex-error dhg-request "unable to find a prime whose size in range [~a, ~a]" min max)]
                                                 [(<= min (car nbits) max) (hash-ref dh-modp-groups (car nbits))]
                                                 [else (seek (cdr nbits))]))))
                         (list min n max))])]))

(define dhg-random : (-> Integer Byte Integer)
  (lambda [p open-min]
    (random-integer (add1 open-min)
                    (quotient (- p 1) 2))))

(define dhg-hash : (-> SSH-Diffie-Hellman-Group-Kex Bytes Integer Integer Integer Bytes)
  (lambda [self K-S e f K]
    (define bits-range : (Listof Index) (unbox (ssh-diffie-hellman-group-kex-bits-range self)))
    (define p : Integer (unbox (ssh-diffie-hellman-group-kex-p self)))
    (define g : Integer (unbox (ssh-diffie-hellman-group-kex-g self)))
    
    ((ssh-kex-hash self)
     (bytes-append (ssh-diffie-hellman-group-kex-VIcs self)
                   (ssh-uint32->bytes (bytes-length K-S)) K-S
                   (apply bytes-append (map ssh-uint32->bytes bits-range))
                   (ssh-mpint->bytes p) (ssh-mpint->bytes g)
                   (ssh-mpint->bytes e) (ssh-mpint->bytes f) (ssh-mpint->bytes K)))))
