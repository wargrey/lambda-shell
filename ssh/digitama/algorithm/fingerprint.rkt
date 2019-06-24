#lang typed/racket/base

(provide (all-defined-out))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-key-fingerprint : (->* (Symbol Bytes) (#:hash (->* (Bytes) (Natural (Option Natural)) Bytes) #:digest (-> Bytes Bytes)) String)
  (lambda [keytype #:hash [hash sha256-bytes] #:digest [digest values] key-raw]
    (define TYPE : String (string-upcase (symbol->string keytype)))
    (define HASH : String (string-upcase (format "~a" (object-name sha256-bytes))))

    (string-append TYPE " " HASH ":" (bytes->string/utf-8 (digest (hash (digest key-raw)))))))
