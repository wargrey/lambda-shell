#lang typed/racket/base

(provide (all-defined-out))

(require racket/unsafe/ops)

(require (for-syntax racket/base))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-syntax (bf-round-do stx)
  (syntax-case stx []
    [(_ l r s p idx)
     #'(unsafe-fxxor (unsafe-fxxor l (unsafe-vector-ref p idx))

                     ; F = ((S1,a + S2,b mod 2^32) XOR S3,c) + S4,d mod 2^32
                     (unsafe-fxand (unsafe-fx+ (unsafe-fxxor (unsafe-fx+ (unsafe-vector-ref s (unsafe-fxand (unsafe-fxrshift r 24) #xFF))
                                                                         (unsafe-vector-ref s (+ (unsafe-fxand (unsafe-fxrshift r 16) #xFF) #x0100)))
                                                             (unsafe-vector-ref s (+ (unsafe-fxand (unsafe-fxrshift r 08) #xFF) #x0200)))
                                               (unsafe-vector-ref s (+ (unsafe-fxand r #xFF) #x0300)))
                                   #xFFFFFFFF))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define bf-blocksize : 8 8)

(define bf-encrypt : (-> Natural Natural (Vectorof Nonnegative-Fixnum) (Vectorof Natural) (Values Nonnegative-Fixnum Nonnegative-Fixnum))
  (lambda [L R P S]
    (let* ([L (unsafe-fxxor L (unsafe-vector-ref P 0))]
           [R (bf-round-do R L S P 01)]
           [L (bf-round-do L R S P 02)]
           [R (bf-round-do R L S P 03)]
           [L (bf-round-do L R S P 04)]
           [R (bf-round-do R L S P 05)]
           [L (bf-round-do L R S P 06)]
           [R (bf-round-do R L S P 07)]
           [L (bf-round-do L R S P 08)]
           [R (bf-round-do R L S P 09)]
           [L (bf-round-do L R S P 10)]
           [R (bf-round-do R L S P 11)]
           [L (bf-round-do L R S P 12)]
           [R (bf-round-do R L S P 13)]
           [L (bf-round-do L R S P 14)]
           [R (bf-round-do R L S P 15)]
           [L (bf-round-do L R S P 16)]
           [R (unsafe-fxxor R (unsafe-vector-ref P 17))])
      (values (unsafe-fxand R #xFFFFFFFF)
              (unsafe-fxand L #xFFFFFFFF)))))

(define bf-decrypt : (-> Natural Natural (Vectorof Nonnegative-Fixnum) (Vectorof Natural) (Values Nonnegative-Fixnum Nonnegative-Fixnum))
  (lambda [L R P S]
    (let* ([L (unsafe-fxxor L (unsafe-vector-ref P 17))]
           [R (bf-round-do R L S P 16)]
           [L (bf-round-do L R S P 15)]
           [R (bf-round-do R L S P 14)]
           [L (bf-round-do L R S P 13)]
           [R (bf-round-do R L S P 12)]
           [L (bf-round-do L R S P 11)]
           [R (bf-round-do R L S P 10)]
           [L (bf-round-do L R S P 09)]
           [R (bf-round-do R L S P 08)]
           [L (bf-round-do L R S P 07)]
           [R (bf-round-do R L S P 06)]
           [L (bf-round-do L R S P 05)]
           [R (bf-round-do R L S P 04)]
           [L (bf-round-do L R S P 03)]
           [R (bf-round-do R L S P 02)]
           [L (bf-round-do L R S P 01)]
           [R (unsafe-fxxor R (unsafe-vector-ref P 0))])
      (values (unsafe-fxand R #xFFFFFFFF)
              (unsafe-fxand L #xFFFFFFFF)))))
