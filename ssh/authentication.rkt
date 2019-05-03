#lang typed/racket/base

(provide (all-defined-out))

(require "digitama/diagnostics.rkt")
(require "digitama/assignment/authentication.rkt")

(require "transport.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-authenticate : (-> SSH-Port (Listof Symbol) Void)
  (lambda [port services]
    (let authenticate ()
      (define datum (sync/enable-break (ssh-port-datum-evt port)))

      (unless (or (eof-object? datum) (exn? datum))
        (when (bytes? datum)
          (define-values (msg _) (ssh-bytes->message datum))

          (displayln msg))
        
        (authenticate)))))
