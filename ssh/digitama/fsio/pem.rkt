#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc7468#section-2

(provide (all-defined-out))

(require racket/string)

(require digimon/binscii)

(define pem-base64-line-size : Positive-Byte 64)

(define pem-write : (-> Bytes (U Output-Port Path-String) #:label (U Symbol String) Void)
  (lambda [key-octets /dev/keyout #:label label-raw]
    (if (not (output-port? /dev/keyout))
        (call-with-output-file* /dev/keyout #:exists 'truncate/replace
          (λ [[/dev/keyout : Output-Port]]
            (pem-write key-octets /dev/keyout #:label label-raw)))
        (let-values ([(BEGIN END) (pem-encapsulation-boundaries label-raw)])
          (displayln BEGIN /dev/keyout)

          (let* ([data (base64-encode key-octets)]
                 [size (bytes-length data)])
            (let write-base64-lines ([idx : Natural 0])
              (when (< idx size)
                (define end : Natural (+ idx (min (abs (- size idx)) pem-base64-line-size)))
                
                (write-bytes data /dev/keyout idx end)
                (newline /dev/keyout)
                
                (write-base64-lines end))))
    
          (displayln END /dev/keyout)
    
          (flush-output /dev/keyout)))))

(define pem-read : (-> (U Input-Port Path-String) #:label (U Symbol String) (Values Bytes Boolean))
  (lambda [/dev/keyin #:label label-raw]
    (if (not (input-port? /dev/keyin))
        (let ([octets.ok? (call-with-input-file* /dev/keyin
                            (λ [[/dev/rsain : Input-Port]] : (List Bytes Boolean)
                              (define-values (octets ok?) (pem-read /dev/rsain #:label label-raw))
                              (list octets ok?)))])
          (values (car octets.ok?) (cadr octets.ok?)))
        (let-values ([(BEGIN END) (pem-encapsulation-boundaries label-raw)])
          (define pre-match? : Boolean
            (let read-head-boundary ()
              (define maybe-line : (U String EOF) (read-line /dev/keyin))
              (cond [(eof-object? maybe-line) #false]
                    [(regexp-match? #px"^[-]+\\s*BEGIN " maybe-line) (string=? BEGIN maybe-line)]
                    [else (read-head-boundary)])))
          
          (define-values (base64s post-match?)
            (let read-key-line : (Values (Listof String) Boolean) ([s46esab : (Listof String) null])
              (define maybe-base64-line : (U String EOF) (read-line /dev/keyin))
              (cond [(eof-object? maybe-base64-line) (values (reverse s46esab) #false)]
                    [(regexp-match? #px"^[-]+\\s*END " maybe-base64-line) (values (reverse s46esab) (string=? maybe-base64-line END))]
                    [(regexp-match? #px"^\\s*$" maybe-base64-line) (read-key-line s46esab)]
                    [else (read-key-line (cons (string-trim maybe-base64-line #:left? #false) s46esab))])))

          (values (base64-decode (apply string-append base64s))
                  (and pre-match? post-match?))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pem-encapsulation-boundaries : (-> (U Symbol String) (Values String String))
  (lambda [label-raw]
    (define label : String
      (string-upcase
       (string-replace
        (cond [(string? label-raw) label-raw]
              [else (symbol->string label-raw)])
        "-" " ")))

    (values (format "-----BEGIN ~a-----" label)
            (format "-----END ~a-----" label))))
