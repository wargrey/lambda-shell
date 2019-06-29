#lang typed/racket/base

(provide (all-defined-out))

(require ssh/digitama/algorithm/rsa)
(require ssh/digitama/fsio/rsa)

(require "cmdenv.rkt")
(require "../cmdenv.rkt")

(define rsa-keygen-main : (-> Any)
  (lambda []
    (define maybe-keyfile : (Option Path-String) (ssh-keyfile))
    (cond [(sshkey-rsa-check-private)
           (unless (not maybe-keyfile)
             (define pem : (Option RSA-Private-Key) (read-rsa maybe-keyfile))
             (define okay? : Boolean (and pem (rsa-key-okay? pem)))

             (unless (not okay?)
               (rsa-pretty-display (assert pem rsa-private-key?) 15))
             
             (if okay? 0 1))]
           [else (let ([rsa (rsa-keygen (rsa-distinct-primes #:modulus-bits (sshkey-rsa-bits)) #:e (sshkey-rsa-public-exponent))])
                   (cond [(not maybe-keyfile) (write-rsa rsa (current-output-port))]
                         [else (write-rsa rsa maybe-keyfile)]))])))
