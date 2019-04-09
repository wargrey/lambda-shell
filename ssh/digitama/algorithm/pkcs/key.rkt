#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require "../../asn-der/sequence.rkt")

(define-asn-sequence rsa-other-prime-info : RSA-Other-Prime-Info
  ([r : asn-integer]
   [d : asn-integer]
   [t : asn-integer]))

(define-asn-sequence ras-other-prime-infos : RSA-Other-Prime-Infos #:of RSA-Other-Prime-Info)

(define-asn-sequence rsa-public-key : RSA-Public-Key
  ([n : asn-integer]   ; modulus
   [e : asn-integer])) ; public exponent

(define-asn-sequence rsa-private-key : RSA-Private-Key
  ([version : asn-integer]
   [n : asn-integer]    ; n
   [e : asn-integer]    ; public exponent
   [d : asn-integer]    ; private exponent
   [p : asn-integer]    ; prime1
   [q : asn-integer]    ; prime2
   [dP : asn-integer]   ; exponent1
   [dQ : asn-integer]   ; exponent2
   [qInv : asn-integer] ; coefficient
   [rdts : RSA-Other-Prime-Infos]))
