#lang typed/racket/base

(provide (all-defined-out))

(require "diagnostics.rkt")

(define ssh-read-bytes : (-> Input-Port Integer Bytes)
  (lambda [/dev/sshin amt]
    (define bs : (U Bytes EOF) (read-bytes amt /dev/sshin))
    (cond [(eof-object? bs) (ssh-raise-eof-error /dev/sshin 'read-binary-packet)]
          [else bs])))

(define ssh-read-special : (All (a) (-> Input-Port (Option Nonnegative-Real) (-> Any Boolean : a) Symbol a))
  (lambda [/dev/sshin timeout ? func]
    (unless (cond [(not timeout) (sync/enable-break /dev/sshin)]
                  [else (sync/timeout/enable-break timeout /dev/sshin)])
      (ssh-raise-timeout-error /dev/sshin 'ssh-accept timeout))

    (define exn-or-datum (read-byte-or-special /dev/sshin))
    (cond [(exn? exn-or-datum) (raise exn-or-datum)]
          [else (assert exn-or-datum ?)])))
