#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690
;;; https://www.strozhevsky.com/free_docs/asn1_in_simple_words.pdf

(provide (all-defined-out))

(require racket/math)
(require math/flonum)
(require digimon/number)

(require "octets.rkt")

(require/typed
 racket/base
 [log (-> Flonum Real Flonum)])

(define default-asn-real-base : (Parameterof Byte) (make-parameter 2))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-real->octets : (->* (Flonum) (Byte) Bytes)
  (lambda [real [base (default-asn-real-base)]]
    (cond [(zero? real) (if (eqv? real -0.0) #"\x43" #"")]
          [(infinite? real) (if (> real 0.0)  #"\x40" #"\x41")]
          [(nan? real) #"\x42"]
          [else (case base
                  [(2) (asn-real-binary real 2)]
                  [(8) (asn-real-binary real 8)]
                  [(16) (asn-real-binary real 16)]
                  [else (asn-real-decimal real)])])))

(define asn-octets->real : (ASN-Octets->Datum Flonum)
  (lambda [breal start end]
    (cond [(<= end start) 0.0]
          [else (let ([infoctet (bytes-ref breal start)])
                  (cond [(bitwise-bit-set? infoctet 7)
                         ; mantissa = sign * (natural << binary-scaling-factor)
                         ; real = mantissa * base ^ exponent
                         (define sign (if (bitwise-bit-set? infoctet 6) -1.0 1.0))
                         (define base-bits (bitwise-bit-field infoctet 4 6))
                         (define binary-scaling-factor (bitwise-bit-field infoctet 2 4))
                         (define exponent-bits (bitwise-and infoctet #b11))
                         (cond [(= base-bits #b00) (asn-binary-real breal start end sign 2.00 binary-scaling-factor exponent-bits)]
                               [(= base-bits #b01) (asn-binary-real breal start end sign 8.00 binary-scaling-factor exponent-bits)]
                               [(= base-bits #b10) (asn-binary-real breal start end sign 16.0 binary-scaling-factor exponent-bits)]
                               [else #| reserved for addenda |# +nan.0])]
                        [(not (bitwise-bit-set? infoctet 6)) ; base 10
                         (cond [(= infoctet #b00000001) (asn-decimal-real breal start end 1)]
                               [(= infoctet #b00000010) (asn-decimal-real breal start end 2)]
                               [(= infoctet #b00000011) (asn-decimal-real breal start end 3)]
                               [else #| reserved for addenda |# +nan.0])]
                        [else ; special values
                         (cond [(= infoctet #b01000000) +inf.0]
                               [(= infoctet #b01000001) -inf.0]
                               [(= infoctet #b01000010) +nan.0]
                               [(= infoctet #b01000011) -0.0]
                               [else #| reserved for addenda |# +nan.0])]))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-real-decimal : (-> Flonum Bytes)
  (lambda [real]
    (define numerical-representation (number->string real))
    
    (if (regexp-match? #px"e" numerical-representation)
        (bytes-append #"\x3" (string->bytes/utf-8 (string-upcase numerical-representation)))
        (bytes-append #"\x1" (string->bytes/utf-8 numerical-representation)))))

(define asn-real-binary : (-> Flonum Byte Bytes)
  (lambda [real base]
    (define-values (E N factor) (asn-real-normalize (flabs real) base))
    (define E-bytes (integer->network-bytes E))
    (define N-bytes (integer->network-bytes N))
    (define E-size (bytes-length E-bytes))
    
    (define infoctet : Byte
      (bitwise-ior (if (> real 0.0)   #b10000000 #b11000000)
                   (cond [(= base 2)  #b00000000]
                         [(= base 8)  #b00010000]
                         [(= base 16) #b00100000]
                         [else        #b00110000 #| deadcode |#])
                   (cond [(= factor 0) #b0000000]
                         [(= factor 1) #b0000100]
                         [(= factor 2) #b0001000]
                         [else         #b0001100])
                   (cond [(= E-size 1) #b0000000]
                         [(= E-size 2) #b0000001]
                         [(= E-size 3) #b0000010]
                         [else         #b0000011])))
    
    (bytes-append (cond [(< E-size 4) (bytes infoctet)]
                        [else (bytes infoctet E-size)])
                  E-bytes N-bytes)))

(define asn-real-normalize : (-> Nonnegative-Flonum Byte (Values Integer Integer Byte))
  (lambda [+real B]
    (define fwhole (exact-floor +real))
    (define base (fl B))
    (let factoring ([fraction : Flonum (- +real fwhole)]
                    [N : Integer fwhole]
                    [E : Integer 0])
      (if (= fraction 0.0)
          (let rshift ([N : Integer N]
                       [F : Index 0])
            (cond [(>= F 3) (values E N 3)]
                  [(odd? N) (values E N F)]
                  [else (rshift (arithmetic-shift N -1) (+ F 1))]))
          (let* ([e (exact-floor (fllogb fraction base))]
                 [m (/ fraction (expt base e))]
                 [mwhole (exact-floor m)])
            (printf "~a * ~a^~a~n" m B e)
            
            (factoring (cond [(integer? m) 0.0]
                             [else (- m mwhole)])
                       (+ (* N B) mwhole)
                       (+ E e)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-binary-real : (-> Bytes Natural Natural Flonum Flonum Byte Byte Flonum)
  (lambda [breal start end S B F E-fmt]
    (define-values (start-offset E-end)
      (cond [(= E-fmt #b00) (values 1 (+ start 2))]
            [(= E-fmt #b01) (values 1 (+ start 3))]
            [(= E-fmt #b10) (values 1 (+ start 4))]
            [(>= (+ start 1) end) (values 2 (+ end 1))] ; overlength
            [else (values 2 (+ start (bytes-ref breal (+ start 1)) 2))]))

    ; R = S * (N << F) * B ^ E
    (cond [(< E-end end)
           (let ([E (network-bytes->integer breal (+ start start-offset) E-end)]
                 [N (network-bytes->integer breal E-end end)])
             (cond [(not (= N 0)) (assert (* (* S (arithmetic-shift N F)) (expt B E)) double-flonum?)]
                   [else 0.0]))]
          [(= E-end end) 0.0]
          [else +nan.0])))

(define asn-decimal-real : (-> Bytes Natural Natural Byte Flonum)
  (lambda [breal start end NR-form] ;;; intend to ignore the numerical representation form
    (cond [(> (+ start 1) end) +nan.0]
          [else (let ([maybe-real (read (open-input-bytes (subbytes breal (+ start 1) end)))])
                  (cond [(double-flonum? maybe-real) maybe-real]
                        [(exact-integer? maybe-real) (exact->inexact maybe-real)]
                        [(real? maybe-real) (real->double-flonum maybe-real)]
                        [else +nan.0]))])))
