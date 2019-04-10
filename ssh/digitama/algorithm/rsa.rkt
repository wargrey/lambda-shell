#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "random.rkt")

(require "pkcs/key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-keygen : (->* () ((List* Positive-Integer Positive-Integer(Listof Positive-Integer)) #:e Positive-Integer) RSA-Private-Key)
  ;; https://tools.ietf.org/html/rfc8017#section-3
  (lambda [[ps (rsa-distinct-primes)] #:e [e0 65537]]
    (define prime1 : Positive-Integer (car ps))
    (define prime2 : Positive-Integer (cadr ps))
    (define modulus : Positive-Integer (apply * ps))
    (define λn : Natural (apply lcm (map sub1 ps)))
    (define public-exponent : Integer
      (cond [(and (<= 3 e0) (< e0 modulus) (coprime? e0 λn)) e0]
            [else (let try-again ()
                    (define maybe-e : Integer (random-integer 3 modulus))
                    (cond [(coprime? maybe-e λn) maybe-e]
                          [else (try-again)]))]))
  
    (define private-exponent : Natural (modular-inverse public-exponent λn))
    (define exponent1 : Natural (remainder private-exponent (sub1 prime1)))
    (define exponent2 : Natural (remainder private-exponent (sub1 prime2)))
    (define coefficient : Natural (modular-inverse prime2 prime1))

    (define other-prime-infos : RSA-Other-Prime-Infos
      (let multi-prime-info ([stdr : RSA-Other-Prime-Infos null]
                             [rs : (Listof Positive-Integer) (cddr ps)]
                             [r.ri-1 : Positive-Integer (* prime1 prime2)])
        (cond [(null? rs) (reverse stdr)]
              [else (let* ([prime_i (car rs)]
                           [exponent_i (remainder private-exponent (sub1 prime_i))]
                           [coefficient_i (modular-inverse r.ri-1 prime_i)])
                      (multi-prime-info (cons (make-rsa-other-prime-info #:r prime_i #:d exponent_i #:t coefficient_i) stdr)
                                        (cdr rs) (* r.ri-1 prime_i)))])))
    
    (make-rsa-private-key #:n modulus #:e public-exponent #:d private-exponent #:p prime1 #:q prime2 #:dP exponent1 #:dQ exponent2 #:qInv coefficient
                          #:version (if (pair? other-prime-infos) 1 0)
                          #:rdts (and (pair? other-prime-infos) other-prime-infos))))

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
