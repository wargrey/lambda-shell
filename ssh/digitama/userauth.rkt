#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "message.rkt")

(define-type SSH-User-Authentication<%>
  (Class (init-field [session-id Bytes])
         [tell-method-name (-> Symbol)]
         [request (-> Symbol Symbol (Option SSH-Message) SSH-Message)]
         [response (-> SSH-Message Symbol Symbol (U SSH-Message Boolean))]
         [abort (-> Void)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-choose-process : (-> Symbol Bytes SSH-User-Authentication<%> (Option (Instance SSH-User-Authentication<%>)) (Instance SSH-User-Authentication<%>))
  (lambda [method-name session-id requested% previous]
    (cond [(not previous) (new requested% [session-id session-id])]
          [(eq? method-name (send previous tell-method-name)) previous]
          [else (send previous abort)
                (new requested% [session-id session-id])])))
