#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "base.rkt")

(define asn-pretty-print : (->* (Bytes) (Integer Integer #:indention Byte #:column Byte #:binary? Boolean #:port Output-Port) Void)
  (lambda [src [start 0] [smart-end 0] #:indention [indention 0] #:column [column 16] #:binary? [base2 #false] #:port [/dev/stdout (current-output-port)]]
    (define idxmax : Index (if (<= smart-end start) (bytes-length src) (assert smart-end index?)))
    (define-values (base inset ~byte) (if (not base2) (values 16 3 byte->hex-string) (values 2 9 byte->bin-string)))
    (define pad : Bytes (make-bytes inset #x20))
    (let print-constructed ([idx : Natural (assert start index?)]
                            [pads : Bytes (make-bytes indention #x20)]
                            [end : Index idxmax])
      (cond [(>= idx idxmax) (void)]
            [(>= idx end) (print-constructed idx (subbytes pads inset) idxmax)]
            [else (let ([identifier (bytes-ref src idx)])
                    (define constructed? : Boolean (asn-identifier-constructed? identifier))
                    (define-values (size idx++) (asn-octets->length src (+ idx 1)))
                    (define content-end : Index (assert (+ idx++ size) index?))
                    
                    (display pads /dev/stdout)
                    (display (~byte identifier))
                    (for ([b (in-bytes src (+ idx 1) idx++)])
                      (fprintf /dev/stdout " ~a" (~byte b)))
                    (newline /dev/stdout)
                    
                    (cond [(and constructed?) (print-constructed idx++ (bytes-append pad pads) content-end)]
                          [else (let print-primitive ([content-idx : Nonnegative-Fixnum (assert idx++ index?)]
                                                      [content-end : Index content-end]
                                                      [column-idx : Byte 1])
                                  (cond [(>= content-idx content-end)
                                         (unless (= column-idx 0) (newline /dev/stdout))
                                         (print-constructed content-end pads end)]
                                        [else (let ([bstr (~byte (bytes-ref src content-idx))])
                                                (when (= column-idx 1)
                                                  (display pad /dev/stdout)
                                                  (display pads /dev/stdout))
                                                (fprintf /dev/stdout (if (= column-idx 0) "~a~n" "~a ") bstr)
                                                (print-primitive (+ content-idx 1) content-end (remainder (+ column-idx 1) column)))]))]))]))))
