#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc2104

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-hmac stx)
  (syntax-case stx []
    [(_ id #:hash HASH #:blocksize B)
     (syntax/loc stx
       (define id : (case-> [Bytes -> (->* (Bytes) (Natural Natural) Bytes)]
                            [Bytes Bytes -> Bytes]
                            [Bytes Bytes Natural -> Bytes]
                            [Bytes Bytes Natural Natural -> Bytes])
         (case-lambda
           [(key-raw)
            (let ([key (if (> (bytes-length key-raw) B) (HASH key-raw) key-raw)])
              (let-values ([(k-ipad k-opad) (hmac-kio-pad key B)])                    
                (λ [[message : Bytes] [start : Natural 0] [end : Natural 0]] : Bytes
                  (HASH (bytes-append k-opad (HASH (hmac-bytes-append k-ipad message start end)))))))]
           [(key-raw message) (id key-raw message 0 0)]
           [(key-raw message start) (id key-raw message start 0)]
           [(key-raw message start end)
            (let*-values ([(key) (if (> (bytes-length key-raw) B) (HASH key-raw) key-raw)]
                          [(k-ipad k-opad) (hmac-kio-pad key B)])         
              (HASH (bytes-append k-opad (HASH (hmac-bytes-append k-ipad message start end)))))])))]
    [(_ id #:hash HASH) (syntax/loc stx (define-hmac id #:hash HASH #:blocksize 64))]))

(define-syntax (define-truncated-hmac stx)
  (syntax-case stx []
    [(_ HMAC #:bits n-bits)
     (with-syntax* ([id (format-id #'HMAC "~a-~a" (syntax-e #'HMAC) (syntax-e #'n-bits))]
                    [n-byte (let ([n (syntax-e #'n-bits)])
                              (cond [(not (exact-positive-integer? n)) (raise-syntax-error 'ssh-truncated-hmac "not a positive integer" #'n-bits)]
                                    [else (let-values ([(q r) (quotient/remainder n 8)])
                                            (cond [(> r 0) (raise-syntax-error 'ssh-truncated-hmac "misaligned bits" #'n-bits)]
                                                  [else (datum->syntax #'n-bits q)]))]))])
       (syntax/loc stx
         (define id : (case-> [Bytes -> (->* (Bytes) (Natural Natural) Bytes)]
                              [Bytes Bytes -> Bytes]
                              [Bytes Bytes Natural -> Bytes]
                              [Bytes Bytes Natural Natural -> Bytes])
           (case-lambda
             [(key) (let ([mac (HMAC key)]) (λ [[message : Bytes] [start : Natural 0] [end : Natural 0]] : Bytes (subbytes (mac message start end) 0 n-byte)))]
             [(key message) (subbytes (HMAC key message 0 0) 0 n-byte)]
             [(key message start) (subbytes (HMAC key message start 0) 0 n-byte)]
             [(key message start end) (subbytes (HMAC key message start end) 0 n-byte)]))))]))

(define-hmac hmac-sha1   #:hash sha1-bytes)
(define-hmac hmac-sha256 #:hash sha256-bytes)

(define-truncated-hmac hmac-sha1   #:bits 96)
(define-truncated-hmac hmac-sha256 #:bits 128)

(define hmac-none : (-> Bytes (->* (Bytes) (Natural Natural) Bytes))
  (lambda [key-raw]
    (λ [[message : Bytes] [start : Natural 0] [end : Natural 0]] : Bytes
      #"")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ipad-byte : Byte #x36)
(define opad-byte : Byte #x5C)

(define hmac-padded-key : (-> Bytes Byte Byte Bytes)
  (lambda [key blocksize pad-byte]
    (cond [(= (bytes-length key) blocksize) key]
          [else (let ([k-pad (make-bytes blocksize pad-byte)])
                  (bytes-copy! k-pad 0 key)
                  k-pad)])))

(define hmac-kio-pad : (-> Bytes Byte (Values Bytes Bytes))
  (lambda [key B]
    (define k-ipad : Bytes (hmac-padded-key key B ipad-byte))
    (define k-opad : Bytes (hmac-padded-key key B opad-byte))
    
    (for ([idx (in-range (bytes-length key))])
      (bytes-set! k-ipad idx (bitwise-xor (bytes-ref k-ipad idx) ipad-byte))
      (bytes-set! k-opad idx (bitwise-xor (bytes-ref k-opad idx) opad-byte)))
    
    (values k-ipad k-opad)))

(define hmac-bytes-append : (->* (Bytes Bytes) (Natural Natural) Bytes)
  (lambda [k-ipad message [start 0] [end0 0]] ; NOTE: this optimizing does not make sense
    (define msg-idx : Index (bytes-length k-ipad))
    (define msg-end : Index (bytes-length message))
    (define end : Natural (if (<= end0 start) msg-end end0))
    (define pool : Bytes (make-bytes (+ msg-idx (- end start))))
    
    (bytes-copy! pool 0 k-ipad 0 msg-idx)
    (bytes-copy! pool msg-idx message start end)

    pool))
