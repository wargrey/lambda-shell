#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690
;;; https://www.strozhevsky.com/free_docs/asn1_in_simple_words.pdf

(provide (all-defined-out))

(require racket/math)
(require math/flonum)
(require digimon/number)

(require "octets.rkt")

(define default-asn-real-base : (Parameterof Byte) (make-parameter 0))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-real->octets : (->* (Flonum) (Byte) Bytes)
  (lambda [real [base (default-asn-real-base)]]
    (cond [(zero? real) (if (eqv? real -0.0) #"\x43" #"")]
          [(infinite? real) (if (> real 0.0) #"\x40" #"\x41")]
          [(nan? real) #"\x42"]
          [(= base 2)  (asn-real-binary real 2.0)]
          [(= base 8)  (asn-real-binary real 8.0)]
          [(= base 10) (asn-real-decimal real)]
          [(= base 16) (asn-real-binary real 16.0)]
          [else (asn-real-smart real)])))

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
(define asn-real-smart : (-> Flonum Bytes)
  (lambda [real]
    #| TODO: auto detect most suitable algorithm |#
    (asn-real-binary real 16.0)))

(define asn-real-decimal : (-> Flonum Bytes)
  (lambda [real]
    (define numerical-representation (number->string real))
    
    (if (regexp-match? #rx"e" numerical-representation)
        (bytes-append #"\x3" (string->bytes/utf-8 (string-upcase numerical-representation)))
        (bytes-append #"\x1" (string->bytes/utf-8 numerical-representation)))))

(define asn-real-binary : (-> Flonum Flonum Bytes)
  (lambda [real base]
    (define +real : Nonnegative-Flonum (flabs real))
    (define-values (E N factor) (asn-real-normalize +real base))
    (cond [(not (fl= +real (asn-real-value 1.0 N base E factor))) (asn-real-decimal real)]
          [else (let ([E-bytes (integer->network-bytes E)]
                      [N-bytes (integer->network-bytes N)])
                  (define E-size (bytes-length E-bytes))
    
                  (define infoctet : Byte
                    (bitwise-ior (cond [(> real 0.0) #b10000000]
                                       [else         #b11000000])
                                 (cond [(= base 2)   #b00000000]
                                       [(= base 8)   #b00010000]
                                       [(= base 16)  #b00100000]
                                       [else         #b00110000 #| deadcode |#])
                                 (cond [(= factor 0) #b00000000]
                                       [(= factor 1) #b00000100]
                                       [(= factor 2) #b00001000]
                                       [else         #b00001100])
                                 (cond [(= E-size 1) #b00000000]
                                       [(= E-size 2) #b00000001]
                                       [(= E-size 3) #b00000010]
                                       [else         #b00000011])))
                  
                  (bytes-append (cond [(< E-size 4) (bytes infoctet)]
                                      [else (bytes infoctet E-size)])
                                E-bytes N-bytes))])))

(define asn-real-normalize : (-> Nonnegative-Flonum Flonum (Values Integer Integer Byte))
  (lambda [+real base]
    ; R = M * b^n = (M * b) * b^(n - 1)
    
    (define-values (E N)
      (let normalize : (Values Integer Integer)
        ([E : Integer 0]
         [r : Flonum +real])
        ; NOTE: `(integer? +max.0)` is true
        (cond [(not (integer? r)) (normalize (- E 1) (* r base))]
              [(= base 16.0) (asn-substitude-trailing-zeros E (exact-floor r) 2 #xFF -8)]
              [(= base 2.0) (asn-substitude-trailing-zeros E (exact-floor r) 8 #xFF -8)]
              [else (asn-substitude-trailing-zeros E (exact-floor r) 8 #xFFFFFF -24)])))

    (asn-real-binary-scale E N)))

(define asn-real-binary-scale : (-> Integer Integer (Values Integer Integer Byte))
  (lambda [E N]
    (let rshift ([N : Integer N]
                 [F : Index 0])
      (cond [(>= F 3) (values E N 3)]
            [(odd? N) (values E N F)]
            [else (rshift (arithmetic-shift N -1) (+ F 1))]))))

(define asn-substitude-trailing-zeros : (-> Integer Integer Byte Natural Integer (Values Integer Integer))
  (lambda [E0 N0 delta mask rshift]
    (let substitute ([E : Integer E0]
                     [N : Integer N0])
      (cond [(> (bitwise-and N mask) 0) (values E N)]
            [else (substitute (+ E delta) (arithmetic-shift N rshift))]))))

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
             (asn-real-value S N B E F))]
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

(define asn-real-value : (-> Flonum Integer Flonum Integer Byte Flonum)
  (lambda [S N B E F]
    (cond [(= N 0) 0.0]
          [(= F 0) (* (* S (fl N)) (flexpt B (fl E)))]
          [else (* (* S (fl (arithmetic-shift N F))) (flexpt B (fl E)))])))
