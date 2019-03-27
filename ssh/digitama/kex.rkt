#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "message.rkt")

(define-type SSH-Key-Exchange<%>
  (Class (init [Vs String] [Vc String]
               [Is Bytes] [Ic Bytes]
               [hostkey String]
               [hash (-> Bytes Bytes)]
               [peer-name Symbol])
         [tell-message-group (-> Symbol)]
         [request (-> SSH-Message)]
         [response (-> SSH-Message (Option SSH-Message))]))
