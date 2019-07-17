#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "state.rkt")

(define words-pretty-print : (->* ((Vectorof Natural)) (Integer Integer #:port Output-Port #:column Positive-Byte #:separator Char) Void)
  (lambda [words [start 0] [smart-end 0] #:port [/dev/stdout (current-output-port)] #:column [column 4] #:separator [separator #\space]]
    (define idxmax : Index (if (<= smart-end start) (vector-length words) (assert smart-end index?)))
    
    (let print-words ([idx : Natural (max start 0)]
                      [column-idx : Index 0])
      (cond [(>= idx idxmax) (when (> column-idx 0) (newline /dev/stdout))]
            [else (let ([bstr (~r (vector-ref words idx) #:base 16 #:min-width 8 #:pad-string "0")])
                    (fprintf /dev/stdout "~a" bstr)

                    (cond [(= column-idx (sub1 column)) (newline /dev/stdout)]
                          [else (fprintf /dev/stdout "~a" separator)])
        
                    (print-words (+ idx 1)
                                 (remainder (+ column-idx 1) column)))]))))

(define state-array-pretty-print : (->* (State-Array) (#:binary? Boolean #:port Output-Port #:separator Char) Void)
  (lambda [s #:binary? [base2 #false] #:port [/dev/stdout (current-output-port)] #:separator [separator #\space]]
    (define-values (rows cols) (state-array-size s))
    (define-values (base ~byte) (if (not base2) (values 16 byte->hex-string) (values 2 byte->bin-string)))
    
    (let rloop ([r : Index 0])
      (when (< r rows)
        (let cloop ([c : Index 0])
          (when (< c cols)
            (fprintf /dev/stdout "~a" (~byte (state-array-ref s r c)))
            
            (cond [(= c (sub1 cols)) (newline /dev/stdout)]
                  [else (fprintf /dev/stdout "~a" separator)])
            
            (cloop (+ c 1))))
        (rloop (+ r 1))))))
