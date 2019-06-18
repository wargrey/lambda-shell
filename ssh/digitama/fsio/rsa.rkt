#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../algorithm/pkcs/key.rkt"))

(require "pem.rkt")

(require "../algorithm/pkcs/key.rkt")
(require "../asn-der/primitive.rkt")
(require "../asn-der/pretty.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-read : (-> (U Input-Port Path-String) (Option RSA-Private-Key))
  (lambda [/dev/rsain]
    (define-values (key-octets rsa?) (pem-read /dev/rsain #:label 'RSA-Private-Key))

    (and rsa? (unsafe-bytes->rsa-private-key* key-octets))))

(define rsa-write : (-> RSA-Private-Key (U Output-Port Path-String) Void)
  (lambda [key /dev/rsaout]
    (pem-write (rsa-private-key->bytes key) /dev/rsaout #:label 'RSA-Private-Key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-pretty-display : (-> RSA-Private-Key Positive-Byte Void)
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

