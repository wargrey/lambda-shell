#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "random.rkt")

(require "pkcs/key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-keygen : (->* () ((List* Integer Integer (Listof Integer)) #:e Integer) RSA-Private-Key)
  ;; https://tools.ietf.org/html/rfc8017#section-3
  (lambda [[ps (rsa-distinct-primes)] #:e [e 65537]]
    (define prime1 : Integer (car ps))
    (define prime2 : Integer (cadr ps))
    (define modulus : Integer (apply * ps))
    (define λn : Natural (apply lcm (map sub1 ps)))
    (define public-exponent : Integer
      (cond [(and (<= 3 e) (< e modulus) (coprime? e λn)) e]
            [else (let try-again ()
                    (define maybe-e : Integer (random-integer 3 modulus))
                    (cond [(coprime? maybe-e λn) maybe-e]
                          [else (try-again)]))]))
  
    (define private-exponent : Natural (modular-inverse public-exponent λn))
    (define exponent1 : Natural (remainder private-exponent (sub1 prime1)))
    (define exponent2 : Natural (remainder private-exponent (sub1 prime2)))
    (define coefficient : Natural (modular-inverse prime2 prime1))

    (define-values (maybe-other-prime-infos version)
      (let multi-prime-info : (Values (Option RSA-Other-Prime-Infos) Integer)
        ([stdr : RSA-Other-Prime-Infos null]
         [rs : (Listof Integer) (cddr ps)]
         [r.ri-1 : Integer (* prime1 prime2)])
        (cond [(null? rs) (if (null? stdr) (values #false 0) (values (reverse stdr) 1))]
              [else (let* ([prime_i (car rs)]
                           [exponent_i (remainder private-exponent (sub1 prime_i))]
                           [coefficient_i (modular-inverse r.ri-1 prime_i)])
                      (multi-prime-info (cons (make-rsa-other-prime-info #:r prime_i #:d exponent_i #:t coefficient_i) stdr)
                                        (cdr rs) (* r.ri-1 prime_i)))])))
    
    (make-rsa-private-key #:n modulus #:e public-exponent #:d private-exponent
                          #:p prime1 #:q prime2 #:dP exponent1 #:dQ exponent2 #:qInv coefficient
                          #:version version #:rdts maybe-other-prime-infos)))

(define rsa-key-okay? : (-> RSA-Private-Key Boolean)
  (lambda [key]
    (define ps : (List* Integer Integer (Listof Integer))
      (list* (rsa-private-key-p key) (rsa-private-key-q key)
             (if (list? (rsa-private-key-rdts key)) (map rsa-other-prime-info-r (rsa-private-key-rdts key)) null)))
    
    (define λn : Natural (apply lcm (map sub1 ps)))
    
    (define e*dmodλn (remainder (* (rsa-private-key-e key) (rsa-private-key-d key)) λn))
    (define e*dPmodp-1 (remainder (* (rsa-private-key-e key) (rsa-private-key-dP key)) (sub1 (rsa-private-key-p key))))
    (define e*dQmodq-1 (remainder (* (rsa-private-key-e key) (rsa-private-key-dQ key)) (sub1 (rsa-private-key-q key))))
    (define q*qInvmodp (remainder (* (rsa-private-key-q key) (rsa-private-key-qInv key)) (sub1 (rsa-private-key-p key))))
    
    (= 1 e*dmodλn e*dPmodp-1 e*dQmodq-1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#|
 π(n) is the number of prime numbers ≤ n.
The prime number theorem states that n/ln(n) is a good approximation of π(n) because when n tends to infinity, π(n)/(n/ln(n)) = 1.

It means the probability that a randomly chosen number is prime is 1/ln(n),
For example, the probability to find a prime number of 1024 bits is 1/(ln(2^1024)) = 1/710
|#

;; also see 'openssl/crypto/rsa/rsa_gen.c'
(define rsa-distinct-primes : (->*() (Byte #:modulus-bits Positive-Index #:retry Positive-Byte)
                                  (List* Positive-Integer Positive-Integer (Listof Positive-Integer)))
  (lambda [[n 2] #:modulus-bits [mbits 2048] #:retry [max-retry 4]]
    (define total : Index (max n 2))
    (define-values (q r) (quotient/remainder mbits total))
    (define-values (nbits+1 nbits+0) (values (assert (+ q 1) index?) q))
    
    (let random-all-primes ()
      (define prime-1st : Positive-Integer (random-odd-prime (if (< 0 r) nbits+1 nbits+0)))

      (let random-primes ([nbits : Index (if (< 1 r) nbits+1 nbits+0)])
        (define prime-2nd : Positive-Integer (random-odd-prime nbits))
        (cond [(eqv? prime-2nd prime-1st) (random-primes nbits)]
              [(<= n 2)
               (cond [(rsa-primes-okay? (list prime-1st prime-2nd) mbits) (list prime-1st prime-2nd)]
                     [else (random-primes nbits)])]
              [else (let random-extra-primes ([eps : (Listof Positive-Integer) null]
                                              [idx : Nonnegative-Fixnum 2]
                                              [retries : Index 0])
                      (define nbits : Index (if (< idx r) nbits+1 nbits+0))
                      (cond [(< idx total)
                             (let ([p (random-odd-prime nbits)])
                               (cond [(memv p eps) (random-extra-primes eps idx 0)]
                                     [else (random-extra-primes (cons p eps) (+ idx 1) 0)]))]
                            [else (let ([all-primes (list* prime-1st prime-2nd (reverse eps))])
                                    (cond [(rsa-primes-okay? all-primes mbits) all-primes]
                                          [(>= retries max-retry) (random-all-primes)]
                                          [else (random-extra-primes (cdr eps) (max (- idx 1) 0) (+ retries 1))]))]))])))))
  
;; also see 'openssl/crypto/bn/bn_rand.c'
(define rsa-primes-okay? : (-> (Listof Positive-Integer) Positive-Index Boolean)
  (lambda [primes mbits]
    (define modulus : Natural (apply * primes))
    (define head-byte : Natural (arithmetic-shift modulus (- 4 mbits)))

    ; #b1000 could be utilized to distinguish a multi-prime private key by using the modulus in a certificate.
    (<= #b1001 head-byte #b1111)))
