#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6

(provide (all-defined-out))

(require typed/racket/class)

(require digimon/system)

(require "rsa.rkt")
(require "pkcs/emsa-v1_5.rkt")

(require "../kex.rkt")
(require "../rsa.rkt")

(require "../../datatype.rkt")

(define ssh-rsa-keyname : Symbol 'ssh-rsa)

(define ssh-rsa% : SSH-Host-Key<%>
  (class object% (super-new)
    (init-field hash-algorithm)
    
    (define key : RSA-Private-Key
      (let ([id-rsa (digimon-path "stone" "hostkey" "id_rsa")])
        (unless (file-exists? id-rsa)
          (rsa-write (rsa-keygen (rsa-distinct-primes #:modulus-bits 2048) #:e 65537)
                     id-rsa))
        (assert (rsa-read id-rsa) rsa-private-key?)))
    
    (define/public (tell-key-name)
      ssh-rsa-keyname)

    (define/public (make-key/certificates)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    (ssh-mpint->bytes (rsa-private-key-e key))
                    (ssh-mpint->bytes (rsa-private-key-n key))))

    ;; https://tools.ietf.org/html/rfc3447#section-8.2.1
    (define/public (make-signature message)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    (ssh-bstring->bytes (rsa-sign key message hash-algorithm))))))
