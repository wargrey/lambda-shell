#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "random.rkt")

(require "pkcs/key.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define rsa-keygen : (->* () ((List* Positive-Integer Positive-Integer(Listof Positive-Integer)) #:e Positive-Integer) RSA-Private)
  ;; https://tools.ietf.org/html/rfc3447#section-3
  (lambda [[ps (rsa-distinct-primes)] #:e [e0 65537]]
    (define p : Positive-Integer (car ps))
    (define q : Positive-Integer (cadr ps))
    (define n : Positive-Integer (apply * ps))
    (define λn : Natural (apply lcm (map sub1 ps)))
    (define e : Positive-Integer
      (cond [(and (<= 3 e0) (< e0 n) (coprime? e0 λn)) e0]
            [else (let try-again ()
                    (define maybe-e : Integer (random-integer 3 n))
                    (cond [(coprime? maybe-e λn) (assert maybe-e exact-positive-integer?)]
                          [else (try-again)]))]))
  
    (define d : Positive-Integer (assert (modular-inverse e λn) exact-positive-integer?))
    (define dP : Positive-Integer (assert (remainder d (sub1 p)) exact-positive-integer?))
    (define dQ : Positive-Integer (assert (remainder d (sub1 q)) exact-positive-integer?))
    (define qInv : Positive-Integer (assert (modular-inverse q p) exact-positive-integer?))
    (rsa-private n e d p q dP dQ qInv
                 (let multi-prime-info : (Listof RSA-Other-Prime-Info)
                   ([stdr : (Listof RSA-Other-Prime-Info) null]
                    [rs : (Listof Positive-Integer) (cddr ps)]
                    [r.ri-1 : Positive-Integer (* p q)])
                   (cond [(null? rs) (reverse stdr)]
                         [else (let* ([ri (car rs)]
                                      [di (assert (remainder d (sub1 ri)) exact-positive-integer?)]
                                      [ti (assert (modular-inverse r.ri-1 ri) exact-positive-integer?)])
                                 (multi-prime-info (cons (rsa-other-prime-info ri di ti) stdr)
                                                   (cdr rs) (* r.ri-1 ri)))])))))

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
