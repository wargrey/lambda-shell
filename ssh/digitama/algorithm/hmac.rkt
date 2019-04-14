#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc2104

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-hmac stx)
  (syntax-case stx []
    [(_ id #:hash HASH #:blocksize B)
     #'(define id : (case-> [Bytes -> (-> Bytes Bytes)]
                            [Bytes Bytes -> Bytes])
         (case-lambda
           [(key-raw)
            (let ([key (if (> (bytes-length key-raw) B) (HASH key-raw) key-raw)])
              (λ [[message : Bytes]] : Bytes
                (let-values ([(k-ipad k-opad) (ssh-kio-pad key B)])                    
                  (HASH (bytes-append k-opad (HASH (bytes-append k-ipad message)))))))]
           [(key-raw message)
            (let*-values ([(key) (if (> (bytes-length key-raw) B) (HASH key-raw) key-raw)]
                          [(k-ipad k-opad) (ssh-kio-pad key B)])         
              (HASH (bytes-append k-opad (HASH (bytes-append k-ipad message)))))]))]
    [(_ id #:hash HASH) #'(define-hmac id #:hash HASH #:blocksize 64)]))

(define-syntax (define-truncated-hmac stx)
  (syntax-case stx []
    [(_ HMAC #:bits n-bits)
     (with-syntax* ([id (format-id #'HMAC "~a-~a" (syntax-e #'HMAC) (syntax-e #'n-bits))]
                    [n-byte (let ([n (syntax-e #'n-bits)])
                              (cond [(not (exact-positive-integer? n)) (raise-syntax-error 'ssh-truncated-hmac "not a positive integer" #'n-bits)]
                                    [else (let-values ([(q r) (quotient/remainder n 8)])
                                            (cond [(> r 0) (raise-syntax-error 'ssh-truncated-hmac "misaligned bits" #'n-bits)]
                                                  [else (datum->syntax #'n-bits q)]))]))])
       #'(define id : (case-> [Bytes -> (-> Bytes Bytes)]
                              [Bytes Bytes -> Bytes])
           (case-lambda
             [(key) (let ([mac (HMAC key)]) (λ [[message : Bytes]] : Bytes (subbytes (mac message) 0 n-byte)))]
             [(key message) (subbytes (HMAC key message) 0 n-byte)])))]))

(define-hmac ssh-hmac-sha1   #:hash sha1-bytes)
(define-hmac ssh-hmac-sha256 #:hash sha256-bytes)

(define-truncated-hmac ssh-hmac-sha1   #:bits 96)
(define-truncated-hmac ssh-hmac-sha256 #:bits 128)

(define ssh-hmac-none : (case-> [Bytes -> (-> Bytes Bytes)]
                                [Bytes Bytes -> Bytes])
  (case-lambda
    [(key-raw) (λ [[message : Bytes]] : Bytes #"")]
    [(key-raw message) #""]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ipad-byte : Byte #x36)
(define opad-byte : Byte #x5C)

(define ssh-padded-key : (-> Bytes Byte Byte Bytes)
  (lambda [key blocksize pad-byte]
    (cond [(= (bytes-length key) blocksize) key]
          [else (let ([k-pad (make-bytes blocksize pad-byte)])
                  (bytes-copy! k-pad 0 key)
                  k-pad)])))

(define ssh-kio-pad : (-> Bytes Byte (Values Bytes Bytes))
  (lambda [key B]
    (define k-ipad : Bytes (ssh-padded-key key B ipad-byte))
    (define k-opad : Bytes (ssh-padded-key key B opad-byte))
    
    (for ([idx (in-range (bytes-length key))])
      (bytes-set! k-ipad idx (bitwise-xor (bytes-ref k-ipad idx) ipad-byte))
      (bytes-set! k-opad idx (bitwise-xor (bytes-ref k-opad idx) opad-byte)))
    
    (values k-ipad k-opad)))
