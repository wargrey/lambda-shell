#lang typed/racket/base

(provide (all-defined-out))

(require math/number-theory)

(require ssh/digitama/algorithm/rsa)
(require ssh/digitama/algorithm/pkcs/key)

(require ssh/digitama/asn-der/primitive)
(require ssh/digitama/asn-der/pretty)

(require ssh/digitama/pem)

(require "cmdenv.rkt")
(require "../cmdenv.rkt")

(define rsa-keygen-main : (-> Any)
  (lambda []
    (define maybe-keyfile : (Option Path-String) (ssh-keyfile))
    (cond [(sshkey-rsa-check-private)
           (unless (not maybe-keyfile)
             (define-values (octets rsa?) (pem-read maybe-keyfile #:label 'RSA-Private-Key))
             (define pem : RSA-Private-Key (unsafe-bytes->rsa-private-key* octets))
             (define okay? : Boolean (rsa-key-okay? pem))

             (unless (not okay?)
               (rsa-key-display pem 15))
             
             (if okay? 0 1))]
           [else (let ([rsa (rsa-keygen (rsa-distinct-primes #:modulus-bits (sshkey-rsa-bits)) #:e (sshkey-rsa-public-exponent))])
                   (define octets : Bytes (rsa-private-key->bytes rsa))
                   (cond [(not maybe-keyfile) (pem-write octets (current-output-port) #:label 'RSA-Private-Key)]
                         [else (pem-write octets maybe-keyfile #:label 'RSA-Private-Key)]))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-key-display : (-> RSA-Private-Key Positive-Byte Void)
  (lambda [pem column]
    (printf "Private Key: (~a bits)~n" (integer-length (rsa-private-key-n pem)))
    (rsa-pretty-print "modulus" (rsa-private-key-n pem) column)
    (printf "public exponent: ~a (0x~a)~n" (rsa-private-key-e pem) (number->string (rsa-private-key-e pem) 16))
    (rsa-pretty-print "private exponent" (rsa-private-key-d pem) column)
    (rsa-pretty-print "exponent1" (rsa-private-key-dP pem) column)
    (rsa-pretty-print "exponent2" (rsa-private-key-dQ pem) column)
    (rsa-pretty-print "coefficient" (rsa-private-key-qInv pem) column)))

(define rsa-pretty-print : (-> String Integer Positive-Byte Void)
  (lambda [name pem column] ; openssl style
    (define /dev/keyout : Output-Port (current-output-port))

    (fprintf /dev/keyout "~a:~n" name)
    (asn-pretty-print #:port /dev/keyout #:separator #\: #:column column
                      (asn-integer->bytes pem))))
