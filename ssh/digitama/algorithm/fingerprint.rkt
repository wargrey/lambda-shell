#lang typed/racket/base

(provide (all-defined-out))

(require racket/symbol)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-key-fingerprint : (->* (Symbol Bytes) (#:hash (->* (Bytes) (Natural (Option Natural)) Bytes) #:digest (-> Bytes Bytes)) String)
  (lambda [keytype #:hash [hash sha256-bytes] #:digest [digest values] key-raw]
    (define TYPE : String (string-upcase (symbol->immutable-string keytype)))
    (define HASH : String (string-upcase (format "~a" (object-name sha256-bytes))))

    (string-append TYPE " " HASH ":" (bytes->string/utf-8 (digest (hash key-raw))))))
