#lang typed/racket/base

(provide (all-defined-out))

(require "../diagnostics.rkt")

(require digimon/exception)

(define-exception exn:ssh:fsio exn:fail:filesystem ()
  (ssh-exn-fsio-message [/dev/stdin : Input-Port] [line : (Option Natural)] [col : (Option Natural)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-exn-fsio-message : (-> Any Input-Port (Option Natural) (Option Natural) String (Values String (Option Continuation-Mark-Set)))
  (lambda [func /dev/stdin line col msg]
    (values (if (and line col)
                (ssh-exn-message func (string-append (format "~a:~a:~a: " (object-name /dev/stdin) line col) msg))
                (ssh-exn-message func (string-append (format "~a: " (object-name /dev/stdin)) msg)))
            #false)))
