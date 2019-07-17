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
                    [state-array-right-shift-word! (format-id #'state-array "~a-right-shift-word!" (syntax-e #'state-array))])
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
                    
                    (when (> padding 0)
                      (bytes-fill! s padding))
                    
                    (let copy-in ([idx : Nonnegative-Fixnum 0])
                      (when (< idx maxidx)
                        (define c : Fixnum (unsafe-fxquotient idx rows))
                        (define r : Byte (unsafe-fxremainder idx rows))
        
                        (unsafe-bytes-set! s (unsafe-fx+ c (* Nb r)) (unsafe-bytes-ref in (unsafe-fx+ idx start)))
                        (copy-in (unsafe-fx+ idx 1))))))

                (define state-array-copy-to-bytes! : (-> (State-Array rows Nb) Bytes Index Void)
                  (lambda [s out start]
                    (let copy-out ([idx : Nonnegative-Fixnum 0])
                      (when (< idx blocksize)
                        (define c : Fixnum (unsafe-fxquotient idx rows))
                        (define r : Byte (unsafe-fxremainder idx rows))
                        
                        (unsafe-bytes-set! out (unsafe-fx+ idx start) (unsafe-bytes-ref s (unsafe-fx+ c (* Nb r))))
                        (copy-out (unsafe-fx+ idx 1))))))

                (define state-array-set! : (-> (State-Array rows Nb) Byte Byte Byte Void)
                  (lambda [s r c v]
                    (unsafe-bytes-set! s (+ c (* Nb r)) v)))
                
                (define state-array-ref : (-> State-Array Byte Byte Byte)
                  (lambda [s r c]
                    (unsafe-bytes-ref s (+ c (* Nb r)))))

                (define state-array-add-round-key! : (-> (State-Array rows Nb) (Vectorof Nonnegative-Fixnum) Nonnegative-Fixnum Void)
                  (lambda [s rotated-schedule start]
                    (let add-round-key ([r : Index 0])
                      (when (< r rows)
                        (define s-idx : Index (unsafe-fx* Nb r))
                        (define self : Index (integer-bytes->uint32 s #false #true s-idx (unsafe-fx+ s-idx 4)))
                        (define keyv : Nonnegative-Fixnum (unsafe-vector-ref rotated-schedule (unsafe-fx+ r start)))
                        
                        (integer->integer-bytes (bitwise-xor self keyv) 4 #false #true s s-idx)
                        
                        (add-round-key (+ r 1))))))

                (define state-array-substitute! : (-> (State-Array rows Nb) Bytes Void)
                  (lambda [s s-box]
                    (let substitute ([idx : Nonnegative-Fixnum 0])
                      (when (< idx blocksize)
                        (unsafe-bytes-set! s idx (unsafe-bytes-ref s-box (unsafe-bytes-ref s idx)))
                        (substitute (+ idx 1))))))

                (define state-array-left-shift-word! : (-> (State-Array rows Nb) Byte Byte Byte Void)
                  (lambda [s r wc bits]
                    (define idx : Nonnegative-Fixnum (+ (* wc 4) (* rows r)))
                    (define v : Index (integer-bytes->uint32 s #false #true idx (unsafe-fx+ idx 4)))
                    
                    (integer->integer-bytes (unsafe-fxxor (unsafe-fxand (unsafe-fxlshift v bits) #xFFFFFFFF)
                                                          (unsafe-fxrshift v (- 32 bits)))
                                            4 #false #true s idx)
                    
                    (void)))
                
                (define state-array-right-shift-word! : (-> (State-Array rows Nb) Byte Byte Byte Void)
                  (lambda [s r wc bits]
                    (define idx : Nonnegative-Fixnum (+ (* wc 4) (* rows r)))
                    (define v : Index (integer-bytes->uint32 s #false #true idx (unsafe-fx+ idx 4)))
                    
                    (integer->integer-bytes (unsafe-fxxor (unsafe-fxrshift v bits)
                                                          (unsafe-fxand (unsafe-fxlshift v (- 32 bits)) #xFFFFFFFF))
                                            4 #false #true s idx)
                    
                    (void)))))]))
