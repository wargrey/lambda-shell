#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "../message.rkt")

(require "../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Constructor (-> SSH-Message SSH-Configuration (U SSH-Channel SSH-Message)))

(define-object ssh-channel : SSH-Channel
  ([name : Symbol]
   [local-id : Index]
   [remote-id : Index]
   [window-size : Index]
   [packet-upsize : Index])
  ())
