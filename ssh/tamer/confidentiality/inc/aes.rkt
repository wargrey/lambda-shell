#lang typed/racket/base

(provide (all-defined-out))
(provide (all-from-out digimon/spec))
(provide (all-from-out "../../../digitama/algorithm/crypto/aes.rkt"))

(require "../../../digitama/algorithm/crypto/aes.rkt")
(require "../../../digitama/algorithm/crypto/aes/state.rkt")

(require digimon/spec)
(require digimon/format)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-behavior (it-check-aes/core! 0xplaintext 0xkey 0xciphertext)
  (let*-values ([(pool) (assert (symb0x->octets 0xplaintext))]
               [(key) (assert (symb0x->octets 0xkey))]
               [(encrypt! decrypt!) (aes-cipher! key)])
    #:it ["encrypt ~s with ~a-bits key ~s" 0xplaintext (* (bytes-length key) 8) 0xkey]
    #:do
    (encrypt! pool)
    (expect-bytes= pool (assert (symb0x->octets 0xciphertext)))))

(define-behavior (it-check-aes/core #:plaintext 0xplaintext #:key 0xkey #:ciphertext 0xciphertext)
  (let*-values ([(plaintext) (assert (symb0x->octets 0xplaintext))]
                [(ciphertext) (assert (symb0x->octets 0xciphertext))]
                [(key) (assert (symb0x->octets 0xkey))]
                [(encrypt decrypt) (aes-cipher key)])
    #:it ["encrypt/decrypt ~s with ~a-bits key ~s" 0xplaintext (* (bytes-length key) 8) 0xkey]
    #:do
    (let* ([ctext (encrypt plaintext)]
           [ptext (decrypt ctext)])
      (expect-bytes= ctext ciphertext)
      (expect-bytes= ptext plaintext))))

(define-behavior (it-check-aes/ctr #:plaintext 0xplaintext #:IV 0xIV #:key 0xkey #:ciphertext 0xciphertext)
  (let*-values ([(plaintext) (assert (symb0x->octets 0xplaintext))]
                [(ciphertext) (assert (symb0x->octets 0xciphertext))]
                [(initial) (assert (symb0x->octets 0xIV))]
                [(key) (assert (symb0x->octets 0xkey))]
                [(encrypt decrypt) (aes-cipher-ctr initial key)])
    #:it ["encrypt/decrypt ~s with ~a-bits key ~s and ~a-bits initial vector ~s"
          0xplaintext
          (* (bytes-length key) 8) 0xkey
          (* (bytes-length initial) 8) 0xIV]
    #:do
    (let* ([ctext (encrypt plaintext)]
           [ptext (decrypt ctext)])
      (expect-bytes= ctext ciphertext)
      (expect-bytes= ptext plaintext))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define aes-mixcolumns! : (-> (State-Array 4 4) Void)
  (lambda [state]
    (aes-mix-columns! state 0 #:encrypt)
    (aes-mix-columns! state 1 #:encrypt)
    (aes-mix-columns! state 2 #:encrypt)
    (aes-mix-columns! state 3 #:encrypt)))

(define aes-state-add-round-key! : (-> (State-Array 4 4) (Vectorof Nonnegative-Fixnum) Byte Void)
  (lambda [state schedule start]
    (aes-state-array-add-round-key! state schedule start)
    (void)))
