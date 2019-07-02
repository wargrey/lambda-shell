#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4419

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "oakley-group.rkt")

(require "../../kex.rkt")
(require "../../message.rkt")
(require "../../diagnostics.rkt")

(require "../../../datatype.rkt")

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

(struct ssh-dhg-kex ssh-kex
  ([VIcs : Bytes]
   [minbits : Positive-Index]
   [reqbits : (Listof Index)]
   [p : Integer]
   [g : Integer]
   [x : Integer]
   [e : Integer])
  #:type-name SSH-DHG-Kex)

(define make-ssh-diffie-hellman-group-exchange : SSH-Kex-Constructor
  (lambda [Vc Vs Ic Is hostkey hash minbits]
    (define VIcs : Bytes
      (bytes-append (ssh-string->bytes Vc) (ssh-string->bytes Vs)
                    (ssh-uint32->bytes (bytes-length Ic)) Ic (ssh-uint32->bytes (bytes-length Is)) Is))

    (ssh-dhg-kex (super-ssh-kex #:name 'diffie-hellman-group-exchange #:hostkey hostkey #:hash hash
                                #:request ssh-diffie-hellman-group-exchange-request
                                #:reply ssh-diffie-hellman-group-exchange-reply
                                #:verify ssh-diffie-hellman-group-exchange-verify)
                 VIcs minbits null 0 0 0 0)))

(define ssh-diffie-hellman-group-exchange-request : SSH-Kex-Request
  (lambda [self]
    (with-asserts ([self ssh-dhg-kex?])
      (define all-prime-sizes : (Listof Index) (sort (hash-keys dh-modp-groups) <))
      (define minbits : Index (car all-prime-sizes))
      (define maxbits : Index (car (reverse all-prime-sizes)))
      (define nbits : Index maxbits)

      (values (struct-copy ssh-dhg-kex self [reqbits (list minbits nbits maxbits)])
              (make-ssh:msg:kex:dh:gex:request #:min minbits #:n nbits #:max maxbits)))))

(define ssh-diffie-hellman-group-exchange-reply : SSH-Kex-Reply
  (lambda [self req]
    (with-asserts ([self ssh-dhg-kex?])
      (cond [(ssh:msg:kex:dh:gex:request:old? req) (dhg-request self req)]
            [(ssh:msg:kex:dh:gex:request? req) (dhg-request self req)]
            [(ssh:msg:kex:dh:gex:init? req) (dhg-reply self req)]
            [else (values self #false)]))))

(define ssh-diffie-hellman-group-exchange-verify : SSH-Kex-Verify
  (lambda [self reply]
    (with-asserts ([self ssh-dhg-kex?])
      (cond [(ssh:msg:kex:dh:gex:group? reply) (dhg-init self reply)]
            [(ssh:msg:kex:dh:gex:reply? reply) (dhg-verify self reply)]
            [else (values self #false)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dhg-request : (-> SSH-DHG-Kex (U SSH-MSG-KEX-DH-GEX-REQUEST-OLD SSH-MSG-KEX-DH-GEX-REQUEST) (Values SSH-Kex SSH-Message))
  (lambda [self req]
    (define-values (dh-group bits-range)
      (cond [(ssh:msg:kex:dh:gex:request:old? req) (dhg-seek self (ssh:msg:kex:dh:gex:request:old-n req))]
            [else (dhg-seek self (ssh:msg:kex:dh:gex:request-min req) (ssh:msg:kex:dh:gex:request-n req) (ssh:msg:kex:dh:gex:request-max req))]))

    (values (struct-copy ssh-dhg-kex self [reqbits bits-range] [p (dh-modp-group-p dh-group)] [g (dh-modp-group-g dh-group)])
            (make-ssh:msg:kex:dh:gex:group #:p (dh-modp-group-p dh-group) #:g (dh-modp-group-g dh-group)))))

(define dhg-init : (-> SSH-DHG-Kex SSH-MSG-KEX-DH-GEX-GROUP (Values SSH-Kex SSH-Message))
  (lambda [self req]
    (define p : Integer (ssh:msg:kex:dh:gex:group-p req))
    (define g : Integer (ssh:msg:kex:dh:gex:group-g req))
    (define x : Integer (dhg-random 1 p)) ; x <- (1, q)
    (define e : Integer (modular-expt g x p))

    (values (struct-copy ssh-dhg-kex self [p p] [g g] [x x] [e e])
            (make-ssh:msg:kex:dh:gex:init #:e e))))

(define dhg-reply : (-> SSH-DHG-Kex SSH-MSG-KEX-DH-GEX-INIT (Values SSH-Kex (Pairof SSH-Message (Pairof Integer Bytes))))
  (lambda [self req]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))

    (define g : Integer (ssh-dhg-kex-g self))
    (define p : Integer (ssh-dhg-kex-p self))
    (define e : Integer (ssh:msg:kex:dh:gex:init-e req))
    (define y : Integer (dhg-random 0 p)) ; y <- (0, q)
    (define f : Integer (modular-expt g y p))
    (define K : Integer (modular-expt e y p))
    (define K-S : Bytes (ssh-hostkey.make-public-key hostkey))
    (define H : Bytes (dhg-hash self K-S e f K))
    (define s : Bytes (ssh-hostkey.sign hostkey H))
    
    (when (or (< e 1) (> e (sub1 p)))
      (ssh-raise-kex-error self "'e' is out of range, expected in [1, p-1]"))

    (values self
            (cons (make-ssh:msg:kex:dh:gex:reply #:K-S K-S #:f f #:s s)
                  (cons K H)))))

(define dhg-verify : (-> SSH-DHG-Kex SSH-MSG-KEX-DH-GEX-REPLY (Values SSH-Kex (Pairof Integer Bytes)))
  (lambda [self reply]
    (define hostkey : SSH-Hostkey (ssh-kex-hostkey self))

    (define p : Integer (ssh-dhg-kex-p self))
    (define x : Integer (ssh-dhg-kex-x self))
    (define e : Integer (ssh-dhg-kex-e self))
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
    
    (values self (cons K H))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define dhg-seek : (case-> [SSH-DHG-Kex Index -> (Values DH-MODP-Group (Listof Index))]
                           [SSH-DHG-Kex Index Index Index -> (Values DH-MODP-Group (Listof Index))])
  (case-lambda
    [(self n)
     (define minbits : Positive-Index (ssh-dhg-kex-minbits self))

     (cond [(< n minbits) (ssh-raise-kex-error dhg-request "the requested prime is too small: (~a < ~a)" n minbits)]
           [else (values (hash-ref dh-modp-groups n (λ [] (ssh-raise-kex-error dhg-request "unable to find the ~a-bits-sized prime" n)))
                         (list n))])]
    [(self smallest preferred biggest)
     (define minbits : Positive-Index (ssh-dhg-kex-minbits self))
     (cond [(not (<= smallest preferred biggest)) (ssh-raise-kex-error dhg-request "invalid prime size range: (~a <= ~a <= ~a)" smallest preferred biggest)]
           [(< biggest minbits) (ssh-raise-kex-error dhg-request "the requested prime is too small: (~a < ~a)" biggest minbits)]
           [else (let ([n (max smallest minbits)])
                   (values (hash-ref dh-modp-groups n
                                     (λ [] (let seek : DH-MODP-Group ([ns : (Listof Index) (sort (hash-keys dh-modp-groups) <)])
                                             (cond [(null? ns) (ssh-raise-kex-error dhg-request "unable to find a prime in range [~a, ~a]" n biggest)]
                                                   [(<= n (car ns) biggest) (hash-ref dh-modp-groups (car ns))]
                                                   [else (seek (cdr ns))]))))
                           (list smallest preferred biggest)))])]))

(define dhg-random : (-> Byte Integer Integer)
  (lambda [open-min p]
    (random-integer (add1 open-min)
                    (quotient (- p 1) 2))))

(define dhg-hash : (-> SSH-DHG-Kex Bytes Integer Integer Integer Bytes)
  (lambda [self K-S e f K]
    (define reqbits : (Listof Index) (ssh-dhg-kex-reqbits self))
    (define p : Integer (ssh-dhg-kex-p self))
    (define g : Integer (ssh-dhg-kex-g self))
    
    ((ssh-kex-hash self)
     (bytes-append (ssh-dhg-kex-VIcs self)
                   (ssh-uint32->bytes (bytes-length K-S)) K-S
                   (apply bytes-append (map ssh-uint32->bytes reqbits))
                   (ssh-mpint->bytes p) (ssh-mpint->bytes g)
                   (ssh-mpint->bytes e) (ssh-mpint->bytes f) (ssh-mpint->bytes K)))))
