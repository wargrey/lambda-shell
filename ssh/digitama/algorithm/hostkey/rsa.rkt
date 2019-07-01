#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6

(provide (all-defined-out))

(require digimon/system)

(require "../rsa.rkt")
(require "../pkcs1/hash.rkt")
(require "../pkcs1/emsa-v1_5.rkt")

(require "../../kex.rkt")
(require "../../fsio/rsa.rkt")

(require "../../../datatype.rkt")

(define ssh-rsa-keyname : Symbol 'ssh-rsa)

(struct ssh-rsa-hostkey ssh-hostkey
  ([private-key : RSA-Private-Key])
  #:type-name SSH-RSA-Hostkey)

(define make-ssh-rsa-hostkey : SSH-Hostkey-Constructor
  (lambda [hash-algorithm minbits]
    (define key : RSA-Private-Key
      (let ([id-rsa (digimon-path 'stone "hostkey" "id_rsa")])
        (unless (file-exists? id-rsa)
          (write-rsa (rsa-keygen (rsa-distinct-primes #:modulus-bits minbits) #:e 65537)
                     id-rsa))
        (assert (read-rsa id-rsa) rsa-private-key?)))

    (ssh-rsa-hostkey ssh-rsa-keyname hash-algorithm
                     ssh-rsa-public-key ssh-rsa-sign
                     key)))

(define ssh-rsa-public-key : SSH-Hostkey-Make-Public-Key
  (lambda [self]
    (rsa-make-public-key (ssh-rsa-hostkey-private-key (assert self ssh-rsa-hostkey?)))))

;; https://tools.ietf.org/html/rfc3447#section-8.2.1
(define ssh-rsa-sign : SSH-Hostkey-Sign
  (lambda [self message]
    (rsa-make-signature (ssh-rsa-hostkey-private-key (assert self ssh-rsa-hostkey?))
                        message (ssh-hostkey-hash self))))

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

(define rsa-bytes->signature-offset : (-> Bytes (Values Symbol Natural))
  (lambda [sig]
    (define-values (algorithm offset) (ssh-bytes->name sig))
    
    (values algorithm (+ offset 4))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-rsa-verify : (-> RSA-Public-Key Bytes Bytes Natural Symbol Boolean)
  (lambda [pubkey message signature sigoff keytype]
    (define hash : PKCS#1-Hash
      (case keytype
        [(rsa-sha2-256) pkcs#1-id-sha256]
        [else pkcs#1-id-sha1]))
    
    (rsa-verify pubkey message signature hash sigoff)))
