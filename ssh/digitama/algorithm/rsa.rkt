#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc3447#section-3

(provide (all-defined-out))

(require math/base)
(require math/number-theory)

(require "random.rkt")

(struct rsa-other-prime-info
  ([r : Positive-Integer]
   [d : Positive-Integer]
   [t : Positive-Integer])
  #:transparent
  #:type-name RSA-Other-Prime-Info)

(struct rsa-private
  (; [version : Boolean] ; whether multi-prime is used, in which case `(pair? rdts)` is true 
   [n : Positive-Integer]    ; modulus
   [e : Positive-Integer]    ; public exponent
   [d : Positive-Integer]    ; private exponent
   [p : Positive-Integer]    ; prime1
   [q : Positive-Integer]    ; prime2
   [dP : Positive-Integer]   ; exponent1
   [dQ : Positive-Integer]   ; exponent2
   [qInv : Positive-Integer] ; coefficient
   [rdts : (Listof RSA-Other-Prime-Info)])
  #:transparent
  #:type-name RSA-Private)

(define ssh-rsa-keygen : (->* () ((List* Positive-Integer Positive-Integer(Listof Positive-Integer)) #:e Positive-Integer) RSA-Private)
  (lambda [[ps (ssh-rsa-distinct-primes)] #:e [e0 65537]]
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

(define ssh-rsa-distinct-primes : (->* () (Index #:bits Positive-Index) (List* Positive-Integer Positive-Integer (Listof Positive-Integer)))
  (lambda [[extra-n 0] #:bits [nbits 1024]]
    (define last-1st : Positive-Integer (random-odd-prime nbits))
    (define last-2nd : Positive-Integer
      (let random-prime ()
        (define maybe-p : Positive-Integer (random-odd-prime nbits))
        (cond [(eqv? maybe-p last-1st) (random-prime)]
              [else maybe-p])))
    
    (let random-prime ([primes : (List* Positive-Integer Positive-Integer (Listof Positive-Integer)) (list last-2nd last-1st)]
                       [n : Fixnum extra-n])
      (cond [(<= n 0) primes]
            [else (let ([p (random-odd-prime nbits)])
                    (cond [(eqv? p primes) (random-prime primes n)]
                          [else (random-prime (cons p primes) (- n 1))]))]))))
