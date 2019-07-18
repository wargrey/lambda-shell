#lang typed/racket/base

;;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf 
;;; https://en.wikipedia.org/wiki/Finite_field_arithmetic

(provide (all-defined-out) integer-bytes->uint32)

(require racket/unsafe/ops)
(require typed/racket/unsafe)

(unsafe-require/typed racket/base
                      [(integer-bytes->integer integer-bytes->uint32) (-> Bytes Boolean Boolean Integer Integer Index)])

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax syntax/parse))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type (State-Array rows Nb) Bytes)

(define-syntax (define-state-array stx)
  (syntax-parse stx
    [(_ id rows:exact-positive-integer Nb:exact-positive-integer)
     (with-syntax* ([blocksize (datum->syntax #'rows (* (syntax-e #'rows) (syntax-e #'Nb)))]
                    [id-Nb (format-id #'id "~a-Nb" (syntax-e #'id))]
                    [id-blocksize (format-id #'id "~a-blocksize" (syntax-e #'id))]
                    [state-array (format-id #'id "~a-state-array" (syntax-e #'id))]
                    [make-state-array (format-id #'state-array "make-~a" (syntax-e #'state-array))]
                    [state-array-copy-from-bytes! (format-id #'state-array "~a-copy-from-bytes!" (syntax-e #'state-array))]
                    [state-array-copy-to-bytes! (format-id #'state-array "~a-copy-to-bytes!" (syntax-e #'state-array))]
                    [state-array-set! (format-id #'state-array "~a-set!" (syntax-e #'state-array))]
                    [state-array-ref (format-id #'state-array "~a-ref" (syntax-e #'state-array))]
                    [state-array-add-round-key! (format-id #'state-array "~a-add-round-key!" (syntax-e #'state-array))]
                    [state-array-substitute! (format-id #'state-array "~a-substitute!" (syntax-e #'state-array))]
                    [state-array-left-shift-word! (format-id #'state-array "~a-left-shift-word!" (syntax-e #'state-array))]
                    [state-array-right-shift-word! (format-id #'state-array "~a-right-shift-word!" (syntax-e #'state-array))]
                    [([r-idx r*Nb r*Nb+4] ...) (for/list ([r (in-range (syntax-e #'rows))])
                                                 (define s-idx (* r (syntax-e #'Nb)))
                                                 (list (datum->syntax #'rows r)
                                                       (datum->syntax #'rows s-idx)
                                                       (datum->syntax #'rows (+ s-idx 4))))]
                    [([bs-idx r*Nb+c] ...) (for/list ([bs (in-range (syntax-e #'blocksize))])
                                                        (define-values (c r)  (quotient/remainder bs (syntax-e #'rows)))
                                                        (list (datum->syntax #'blocksize bs)
                                                              (datum->syntax #'blocksize (+ c (* r (syntax-e #'Nb))))))])
       #'(begin (define id-Nb : Nb Nb)
                (define id-blocksize : blocksize blocksize)

                (define make-state-array : (-> (State-Array rows Nb))
                  (lambda []
                    (make-bytes blocksize)))

                (define state-array-copy-from-bytes! : (->* ((State-Array rows Nb) Bytes) (Index Index) Void)
                  (lambda [s in [start 0] [end0 0]]
                    (define end : Index (if (<= end0 start) (bytes-length in) end0))
                    (define padding : Fixnum (- (+ start blocksize) end))
                    (define maxidx : Fixnum (if (> padding 0) (- blocksize padding) blocksize))
                    
                    (if (> padding 0)
                        (void (bytes-fill! s padding)
                              (let copy-in ([idx : Nonnegative-Fixnum 0])
                                (when (< idx maxidx)
                                  (define c : Fixnum (unsafe-fxquotient idx rows))
                                  (define r : Byte (unsafe-fxremainder idx rows))
                                  
                                  (unsafe-bytes-set! s (unsafe-fx+ c (* Nb r)) (unsafe-bytes-ref in (unsafe-fx+ idx start)))
                                  (copy-in (unsafe-fx+ idx 1)))))
                        (void (unsafe-bytes-set! s r*Nb+c (unsafe-bytes-ref in (unsafe-fx+ bs-idx start)))
                              ...))))

                (define state-array-copy-to-bytes! : (-> (State-Array rows Nb) Bytes Nonnegative-Fixnum Void)
                  (lambda [s out start]
                    (unsafe-bytes-set! out (unsafe-fx+ bs-idx start) (unsafe-bytes-ref s r*Nb+c))
                    ...))

                (define-syntax (state-array-set! stx)
                  (syntax-case stx []
                    [(_ s r c v) #'(unsafe-bytes-set! s (+ c (* Nb r)) v)]))
                
                (define-syntax (state-array-ref stx)
                  (syntax-case stx []
                    [(_ s r c) #'(unsafe-bytes-ref s (+ c (* Nb r)))]))

                ;; WARNING
                ; This is not a generic function, it only works when Nb = 4,
                ; But it is also easy to generalization in the future
                (define-syntax (state-array-add-round-key! stx)
                  (syntax-case stx []
                    [(_ s rotated-schedule start)
                     #'(begin (let ([self (integer-bytes->uint32 s #false #true r*Nb r*Nb+4)]
                                    [keyv (unsafe-vector-ref rotated-schedule (unsafe-fx+ r-idx start))])
                                (integer->integer-bytes (bitwise-xor self keyv) 4 #false #true s r*Nb))
                              ...)]))
                
                (define state-array-substitute! : (-> (State-Array rows Nb) Bytes Void)
                  (lambda [s s-box]
                    (unsafe-bytes-set! s bs-idx (unsafe-bytes-ref s-box (unsafe-bytes-ref s bs-idx)))
                    ...))

                (define-syntax (state-array-left-shift-word! stx)
                  (syntax-case stx []
                    [(_ s r wc bits)
                     #'(let* ([idx (+ (* wc 4) (* rows r))]
                              [v (integer-bytes->uint32 s #false #true idx (unsafe-fx+ idx 4))])           
                         (integer->integer-bytes (unsafe-fxxor (unsafe-fxand (unsafe-fxlshift v bits) #xFFFFFFFF)
                                                               (unsafe-fxrshift v (- 32 bits)))
                                                 4 #false #true s idx))]))
                
                (define-syntax (state-array-right-shift-word! stx)
                  (syntax-case stx []
                    [(_ s r wc bits)
                     #'(let* ([idx (+ (* wc 4) (* rows r))]
                              [v (integer-bytes->uint32 s #false #true idx (unsafe-fx+ idx 4))])
                         (integer->integer-bytes (unsafe-fxxor (unsafe-fxrshift v bits)
                                                               (unsafe-fxand (unsafe-fxlshift v (- 32 bits)) #xFFFFFFFF))
                                                 4 #false #true s idx))]))))]))
