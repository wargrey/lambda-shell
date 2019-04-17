#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(define words-pretty-print : (->* (Bytes) (Integer Integer #:binary? Boolean #:port Output-Port #:size Positive-Byte #:column Positive-Byte #:separator Char) Void)
  (lambda [words [start 0] [smart-end 0]
                #:binary? [base2 #false] #:port [/dev/stdout (current-output-port)]
                #:size [size 4] #:column [column 4] #:separator [separator #\space]]
    (define idxmax : Index (if (<= smart-end start) (bytes-length words) (assert smart-end index?)))
    (define-values (base ~byte) (if (not base2) (values 16 byte->hex-string) (values 2 byte->bin-string)))
    (define column-boundary : Index (* size column))
    
    (let print-words ([idx : Natural (assert start index?)]
                      [word-idx : Byte 0]
                      [column-idx : Index 0])
      (cond [(>= idx idxmax) (when (> column-idx 0) (newline /dev/stdout))]
            [else (let ([bstr (~byte (bytes-ref words idx))])
                    (fprintf /dev/stdout "~a" bstr)

                    (cond [(= column-idx (sub1 column-boundary)) (newline /dev/stdout)]
                          [(= word-idx (sub1 size)) (fprintf /dev/stdout "~a" separator)])
        
                    (print-words (+ idx 1)
                                 (remainder (+ word-idx 1) size)
                                 (remainder (+ column-idx 1) column-boundary)))]))))
