#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "message.rkt")

(define-type SSH-User-Authentication<%>
  (Class (init-field [session-id Bytes] [username Symbol] [service Symbol])
         [tell-message-group (-> Symbol)]
         [request (-> (Option SSH-Message) SSH-Message)]
         [response (-> SSH-Message (Option SSH-Message))]
         [done? (-> Boolean)]))
