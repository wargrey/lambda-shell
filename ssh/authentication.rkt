#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-User-Port)

(require "digitama/authentication.rkt")
(require "digitama/diagnostics.rkt")

(require "transport.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-authenticate : (-> SSH-Port Void)
  (lambda [port]
    (printf "--------->: ~s~n"
            (ssh-port-session-identity port))))
