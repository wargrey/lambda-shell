#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6

(provide (all-defined-out))

(require typed/racket/class)

(require digimon/system)

(require "../rsa.rkt")
(require "../pkcs1/hash.rkt")
(require "../pkcs1/emsa-v1_5.rkt")

(require "../../kex.rkt")
(require "../../fsio/rsa.rkt")

(require "../../../datatype.rkt")

(define ssh-rsa-keyname : Symbol 'ssh-rsa)

(define ssh-rsa% : SSH-Host-Key<%>
  (class object% (super-new)
    (init-field hash-algorithm)
    
    (define key : RSA-Private-Key
      (let ([id-rsa (digimon-path 'stone "hostkey" "id_rsa")])
        (unless (file-exists? id-rsa)
          (write-rsa (rsa-keygen (rsa-distinct-primes #:modulus-bits 2048) #:e 65537)
                     id-rsa))
        (assert (read-rsa id-rsa) rsa-private-key?)))
    
    (define/public (tell-key-name)
      ssh-rsa-keyname)

    (define/public (make-pubkey/certificates)
      (rsa-make-public-key key))

    ;; https://tools.ietf.org/html/rfc3447#section-8.2.1
    (define/public (make-signature message)
      (rsa-make-signature key message hash-algorithm))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-make-public-key : (-> RSA-Private-Key Bytes)
  (lambda [key]
    (bytes-append (ssh-name->bytes ssh-rsa-keyname)
                  (ssh-mpint->bytes (rsa-private-key-e key))
                  (ssh-mpint->bytes (rsa-private-key-n key)))))

(define rsa-bytes->public-key : (-> Bytes RSA-Public-Key)
  (lambda [key]
    (let*-values ([(_ offset) (ssh-bytes->string key)]
                  [(e offset) (ssh-bytes->mpint key offset)]
                  [(n offset) (ssh-bytes->mpint key offset)])
      (make-rsa-public-key #:e e #:n n))))

(define rsa-make-signature : (-> RSA-Private-Key Bytes PKCS#1-Hash Bytes)
  (lambda [key message hash]
    (define keytype : Symbol
      (cond [(eq? hash pkcs#1-id-sha256) 'rsa-sha2-256]
            [else ssh-rsa-keyname]))
    
    (bytes-append (ssh-name->bytes keytype)
                  (ssh-bstring->bytes (rsa-sign key message hash)))))

(define rsa-bytes->signature : (-> Bytes (Values Symbol Bytes))
  (lambda [sig]
    (define-values (algorithm offset) (ssh-bytes->name sig))

    (values algorithm (subbytes sig (+ offset 4)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-rsa-verify : (-> RSA-Public-Key Bytes Bytes Symbol Boolean)
  (lambda [pubkey message signature keytype]
    (define hash : PKCS#1-Hash
      (case keytype
        [(rsa-sha2-256) pkcs#1-id-sha256]
        [else pkcs#1-id-sha1]))
    
    (rsa-verify pubkey message signature hash)))
