#lang typed/racket/base

(provide (all-defined-out))

(require digimon/format)

(require "base.rkt")

(define asn-dissect : (->* (Bytes) (Integer Integer #:binary? Boolean #:port Output-Port #:indention Byte #:column Positive-Byte #:separator Char) Void)
  (lambda [basn [start 0] [smart-end 0]
                #:binary? [base2 #false] #:port [/dev/stdout (current-output-port)]
                #:indention [indention 0] #:column [column 16] #:separator [separator #\space]]
    (define idxmax : Index (if (<= smart-end start) (bytes-length basn) (assert smart-end index?)))
    (define-values (base inset ~byte) (if (not base2) (values 16 3 byte->hex-string) (values 2 9 byte->bin-string)))
    (define pad : Bytes (make-bytes inset #x20))
    (define fmt : String (string-append (string separator) "~a"))

    (let print-constructed ([idx : Natural (assert start exact-nonnegative-integer?)]
                            [pads : Bytes (make-bytes indention #x20)]
                            [end : Index idxmax])
      (cond [(>= idx idxmax) (void)]
            [(>= idx end) (print-constructed idx (subbytes pads inset) idxmax)]
            [else (let ([identifier (bytes-ref basn idx)])
                    (define constructed? : Boolean (asn-identifier-constructed? identifier))
                    (define-values (size idx++) (asn-octets->length basn (+ idx 1)))
                    (define content-end : Index (assert (+ idx++ size) index?))
                    
                    (display pads /dev/stdout)
                    (display (~byte identifier) /dev/stdout)
                    (for ([b (in-bytes basn (+ idx 1) idx++)])
                      (fprintf /dev/stdout " ~a" (~byte b)))
                    
                    (cond [(and constructed?)
                           (newline /dev/stdout)
                           (print-constructed idx++ (bytes-append pad pads) content-end)]
                          [else (let print-primitive ([content-idx : Natural idx++]
                                                      [content-end : Index content-end]
                                                      [column-idx : Byte 0])
                                  (cond [(>= content-idx content-end)
                                         (newline /dev/stdout)
                                         (print-constructed content-end pads end)]
                                        [else (let ([bstr (~byte (bytes-ref basn content-idx))])
                                                (when (= column-idx 0)
                                                  (newline /dev/stdout)
                                                  (display pad /dev/stdout)
                                                  (display pads /dev/stdout))
                                                (fprintf /dev/stdout (if (= column-idx 0) "~a" fmt) bstr)
                                                (print-primitive (+ content-idx 1) content-end (remainder (+ column-idx 1) column)))]))]))]))))
