#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))
(provide (rename-out [rsa-key-n rsa-public-n]
                     [rsa-key-e rsa-public-e]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct rsa-other-prime-info
  ([r : Positive-Integer]
   [d : Positive-Integer]
   [t : Positive-Integer])
  #:transparent
  #:type-name RSA-Other-Prime-Info)

(struct rsa-key
  ([n : Positive-Integer]    ; modulus
   [e : Positive-Integer])   ; public exponent
  #:transparent
  #:type-name RSA-Key)

(struct rsa-public rsa-key
  ()
  #:transparent
  #:type-name RSA-Public)

(struct rsa-private rsa-key
  (; [version : Boolean] ; `version` implies `(pair? rdts)`
   [d : Positive-Integer]    ; private exponent
   [p : Positive-Integer]    ; prime1
   [q : Positive-Integer]    ; prime2
   [dP : Positive-Integer]   ; exponent1
   [dQ : Positive-Integer]   ; exponent2
   [qInv : Positive-Integer] ; coefficient
   [rdts : (Listof RSA-Other-Prime-Info)])
  #:transparent
  #:type-name RSA-Private)
