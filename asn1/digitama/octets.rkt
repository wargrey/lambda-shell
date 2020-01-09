#lang typed/racket/base

(provide (all-defined-out))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-asn-bytes->maybe-datum : (All (T V) (-> (->* (Bytes) (Integer) Boolean) (->* (Bytes) (Natural) (Values T Natural)) V
                                                     (->* (Bytes) (Natural) (Values (U T V) Natural))))
  (lambda [asn-octets? bytes->asn defval]
    (λ [[basn : Bytes] [offset : Natural 0]] : (Values (U T V) Natural)
      (cond [(asn-octets? basn offset) (bytes->asn basn offset)]
            [else (values defval offset)]))))
