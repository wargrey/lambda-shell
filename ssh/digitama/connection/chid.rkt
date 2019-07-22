#lang typed/racket/base

(provide (all-defined-out))

(define make-ssh-channel-id : (-> Index)
  (let ([metrics ((inst make-vector Integer) 12)])
    (lambda []
      (vector-set-performance-stats! metrics)

      (let ([uptime (vector-ref metrics 0)]
            [memory+jit (+ (current-memory-use) (vector-ref metrics 10))]
            [hash-count (vector-ref metrics 8)])
        (define id : Integer
          (bitwise-ior (arithmetic-shift hash-count 24)
                       (arithmetic-shift uptime 08)
                       (bitwise-and memory+jit #xFF)))
        
        (assert (bitwise-and #xFFFFFFFF id) index?)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-channel-uuid : (-> (-> Index) HashTableTop Index)
  (lambda [make-id idbase]
    (let uuid ()
      (define id : Index (make-id))

      (if (hash-has-key? idbase id) (uuid) id))))
