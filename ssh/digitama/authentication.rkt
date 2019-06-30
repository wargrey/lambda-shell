#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")
(require "userauth.rkt")

(require "authentication/option.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define userauth-choose-process : (-> Symbol Bytes SSH-Userauth-Constructor (Option SSH-Userauth) SSH-Userauth)
  (lambda [method-name session-id make-userauth previous]
    (cond [(not previous) (make-userauth session-id)]
          [(eq? method-name (ssh-userauth-name previous)) previous]
          [else (let ([abort (ssh-userauth-abort previous)])
                  (and abort (abort previous))
                  (make-userauth session-id))])))
