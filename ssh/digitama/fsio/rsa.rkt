#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out "../algorithm/pkcs1/key.rkt"))

(require "pem.rkt")

(require "../algorithm/pkcs1/key.rkt")
(require "../asn-der/primitive.rkt")
(require "../asn-der/pretty.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define read-rsa : (-> (U Input-Port Path-String) (Option RSA-Private-Key))
  (lambda [/dev/rsain]
    (define-values (key-octets BEGIN END) (pem-read /dev/rsain))

    (and (eq? BEGIN END)
         (pem-label-equal? '|RSA PRIVATE KEY| BEGIN)
         (unsafe-bytes->rsa-private-key* key-octets))))

(define write-rsa : (-> RSA-Private-Key (U Output-Port Path-String) Void)
  (lambda [key /dev/rsaout]
    (pem-write (rsa-private-key->bytes key) /dev/rsaout #:label 'RSA-Private-Key)))

(define read-rsa-pub : (-> (U Input-Port Path-String) (Option RSA-Public-Key))
  (lambda [/dev/rsain]
    (define-values (key-octets BEGIN END) (pem-read /dev/rsain))

    (asn-pretty-print #:separator #\: #:column 24
                      key-octets)

    (and (eq? BEGIN END)
         (pem-label-equal? '|RSA PUBLIC KEY| BEGIN)
         (unsafe-bytes->rsa-public-key* key-octets))))

(define write-rsa-pub : (-> (U RSA-Private-Key RSA-Public-Key) (U Output-Port Path-String) Void)
  (lambda [key /dev/rsaout]
    (define pubkey : RSA-Public-Key
      (cond [(rsa-public-key? key) key]
            [else (let ([n : Integer (rsa-private-key-n key)]
                        [e : Integer (rsa-private-key-e key)])
                    (make-rsa-public-key #:n n #:e e))]))
    
    (pem-write (rsa-public-key->bytes pubkey) /dev/rsaout #:label 'RSA-Public-Key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-pretty-display : (-> (U RSA-Private-Key RSA-Public-Key) Positive-Byte Void)
  (lambda [pem column]
    (define-values (type n e)
      (if (rsa-private-key? pem)
          (values "Private" (rsa-private-key-n pem) (rsa-private-key-e pem))
          (values "Public" (rsa-public-key-n pem) (rsa-public-key-e pem))))
    
    (printf "~a Key: (~a bits)~n" type (integer-length n))
    (rsa-pretty-print "modulus" n column)
    (printf "public exponent: ~a (0x~a)~n" e (number->string e 16))

    (when (rsa-private-key? pem)
      (rsa-pretty-print "private exponent" (rsa-private-key-d pem) column)
      (rsa-pretty-print "exponent1" (rsa-private-key-dP pem) column)
      (rsa-pretty-print "exponent2" (rsa-private-key-dQ pem) column)
      (rsa-pretty-print "coefficient" (rsa-private-key-qInv pem) column))))

(define rsa-pretty-print : (-> (Option String) Integer Positive-Byte Void)
  (lambda [name n column] ; openssl style
    (define /dev/keyout : Output-Port (current-output-port))

    (when (and name (> (string-length name) 0))
      (fprintf /dev/keyout "~a:~n" name))

    (asn-pretty-print #:port /dev/keyout #:separator #\: #:column column
                      (asn-integer->bytes n))))

