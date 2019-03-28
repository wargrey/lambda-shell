#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc3447#section-3

(provide (all-defined-out))

(require "random.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#|
 π(n) is the number of prime numbers ≤ n.
The prime number theorem states that n/ln(n) is a good approximation of π(n) because when n tends to infinity, π(n)/(n/ln(n)) = 1.

It means the probability that a randomly chosen number is prime is 1/ln(n),
For example, the probability to find a prime number of 1024 bits is 1/(ln(2^1024)) = 1/710
|#

(define ssh-rsa-distinct-primes : (->* (Index) (Positive-Index) (Listof Natural))
  (lambda [n [nbits 1024]]
    (let random-prime ([primes : (Listof Natural) null]
                       [n : Fixnum n])
      (cond [(<= n 0) primes]
            [else (let ([p (random-odd-prime nbits)])
                    (cond [(member p primes) (random-prime primes n)]
                          [else (random-prime (cons p primes) (- n 1))]))]))))

(define ssh-rsa-keygen : (-> (Values Natural Natural))
  (lambda []
    (values 0 0)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
