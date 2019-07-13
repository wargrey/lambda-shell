#lang typed/racket/base

(provide (all-defined-out))

(define bodybits : Byte 26)
(define randbits : Byte 4)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-eq-uuid : (case-> [Any -> Index]
                                      [Any HashTableTop -> Index])
  (case-lambda
    [(object)
     (assert (let ([body (bitwise-bit-field (eq-hash-code object) 0 bodybits)]
                   [rand (random (arithmetic-shift 1 randbits))])
               (bitwise-ior (arithmetic-shift rand bodybits) body))
             index?)]
    [(object uuidbase)
     (let uuid ([composed-object : Any object])
      (let ([id (ssh-channel-eq-uuid composed-object)])
        (cond [(not (hash-has-key? uuidbase id)) id]
              [else (uuid (cons composed-object id))])))]))
