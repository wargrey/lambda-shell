#lang typed/racket/base

(provide (all-defined-out))

(require ssh/digitama/algorithm/rsa)
(require ssh/digitama/algorithm/pkcs/key)

(require ssh/digitama/asn-der/pretty)
(require ssh/digitama/pem)

(require "cmdenv.rkt")
(require "../cmdenv.rkt")

(define rsa-keygen-main : (-> Any)
  (lambda []
    (define maybe-keyfile : (Option Path-String) (ssh-keyfile))
    (if (sshkey-rsa-check-private)

        (unless (not maybe-keyfile)
          (define-values (octets okay?) (pem-read maybe-keyfile #:label 'RSA-Private-Key))
          (asn-pretty-print octets)
          (unsafe-bytes->rsa-private-key* octets))
        
        (let ([rsa (rsa-keygen (rsa-distinct-primes #:modulus-bits (sshkey-rsa-bits)) #:e (sshkey-rsa-public-exponent))])
          (define octets : Bytes (rsa-private-key->bytes rsa))
          (cond [(not maybe-keyfile) (pem-write octets (current-output-port) #:label 'RSA-Private-Key)]
                [else (pem-write octets maybe-keyfile #:label 'RSA-Private-Key)])))))
