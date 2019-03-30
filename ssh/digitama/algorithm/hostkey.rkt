#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6

(provide (all-defined-out))

(require racket/string)

(require typed/racket/class)

(require digimon/binscii)

(require "rsa.rkt")

(require "../../datatype.rkt")
(require "../kex.rkt")

(define ssh-rsa-keyname : Symbol 'ssh-rsa)

(define ssh-rsa% : SSH-Host-Key<%>
  (class object% (super-new)
    (init-field [hash sha1-bytes])
    
    (define key : RSA-Private
      (let ([primes (rsa-distinct-primes #:bits 1024)])
        (rsa-keygen primes #:e 17)))
    
    (define/public (tell-key-name)
      ssh-rsa-keyname)

    (define/public (make-key/certificates)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    (ssh-mpint->bytes (rsa-private-e key))
                    (ssh-mpint->bytes (rsa-private-n key))))

    ;; https://tools.ietf.org/html/rfc3447#section-8.2.1
    (define/public (make-signature message)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    ))))
