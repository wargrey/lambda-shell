#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "message.rkt")
(require "algorithm/pkcs1/hash.rkt")

(define-type SSH-Host-Key<%>
  (Class (init-field [hash-algorithm PKCS#1-Hash])
         [tell-key-name (-> Symbol)]
         [make-key/certificates (-> Bytes)]
         [make-signature (-> Bytes Bytes)]))

(define-type SSH-Key-Exchange<%>
  (Class (init [Vc String] [Vs String]
               [Ic Bytes] [Is Bytes]
               [hostkey (Instance SSH-Host-Key<%>)]
               [hash (-> Bytes Bytes)])
         [tell-message-group (-> Symbol)]
         [tell-secret (-> (Values Integer Bytes))]
         [request (-> SSH-Message)]
         [response (-> SSH-Message (Option SSH-Message))]
         [done? (-> Boolean)]))
