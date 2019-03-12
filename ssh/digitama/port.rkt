#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)

(require "identification.rkt")
(require "transport.rkt")
(require "exception.rkt")

(define ssh-connect : (-> String Integer
                          [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)]
                          (Values Input-Port Output-Port))
  (lambda [hostname port #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]]
    (define-values (/dev/tcpin /dev/tcpout) (tcp-connect hostname port))
    (define-values (identification idsize) (make-identification protoversion (or softwareversion "") comments))
    (write-string identification /dev/tcpout 0 idsize)
    (sync /dev/tcpin)
    (read-server-identification /dev/tcpin)
    (values /dev/tcpin /dev/tcpout)))

(define ssh-connect/enable-break : (-> String Integer
                                       [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)] [#:timeout (Option Nonnegative-Real)]
                                       (Values Input-Port Output-Port))
  (lambda [hostname port #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false] #:timeout [timeout #false]]
    (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
    (define-values (identification idsize) (make-identification protoversion (or softwareversion "") comments))
    (write-string identification /dev/tcpout 0 idsize)
    (unless (cond [(not timeout) (sync/enable-break /dev/tcpin)]
                  [else (sync/timeout/enable-break timeout /dev/tcpin)])
      (throw-timeout-error 'ssh-connect/enable-break))
    (read-server-identification /dev/tcpin)
    (values /dev/tcpin /dev/tcpout)))
