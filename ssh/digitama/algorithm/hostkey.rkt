#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6

(provide (all-defined-out))

(require typed/racket/class)

(require digimon/binscii)

(require "rsa.rkt")
(require "pkcs/key.rkt")
(require "pkcs/emsa-v1_5.rkt")

(require "../kex.rkt")

(require "../../datatype.rkt")

(define ssh-rsa-keyname : Symbol 'ssh-rsa)

(define ssh-rsa% : SSH-Host-Key<%>
  (class object% (super-new)
    (init-field hash-algorithm peer-name)
    
    (define key : RSA-Private-Key
      (let ([temp-rsa (build-path (find-system-path 'temp-dir) "rsa.primes")])
        (unless (file-exists? temp-rsa)
          (call-with-output-file* temp-rsa
            (λ [[/dev/rsaout : Output-Port]]
              (write (rsa-distinct-primes #:modulus-bits 1024) /dev/rsaout))))
        (call-with-input-file* temp-rsa
          (λ [[/dev/rsain : Input-Port]]
            (rsa-keygen (cast (read /dev/rsain) (List* Positive-Integer Positive-Integer (Listof Positive-Integer))) #:e 17)))))
    
    (define/public (tell-key-name)
      ssh-rsa-keyname)

    (define/public (make-key/certificates)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    (ssh-mpint->bytes (rsa-private-key-e key))
                    (ssh-mpint->bytes (rsa-private-key-n key))))

    ;; https://tools.ietf.org/html/rfc3447#section-8.2.1
    (define/public (make-signature message)
      (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                    (ssh-bstring->bytes (rsa-sign key message hash-algorithm peer-name))))))
