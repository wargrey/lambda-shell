#lang typed/racket/base

(provide (except-out (all-defined-out) define-make-disconnection define-make-disconnections))

(require "name.rkt")
(require "../message/transport.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

;; NOTE
; Macros that defined in typed racket cannot be used in untyped environment directly,
; so that `dynamic-require-for-syntax` is used here to surpass the problem.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-syntax (define-make-disconnection stx)
  (syntax-case stx [:]
    [(_ REASON)
     (with-syntax* ([id (format-id #'REASON "make-~a" (syntax-e (ssh-typeid #'REASON)))])
       #'(define id : (->* () ((Option String) #:language (Option Symbol)) #:rest Any SSH-MSG-DISCONNECT)
           (lambda [#:language [lang #false] [descfmt #false] . argl]
             (let ([desc (and descfmt (if (null? argl) descfmt (apply format descfmt argl)))])
               (make-ssh:msg:disconnect #:reason 'REASON #:description desc #:language lang)))))]))

(define-syntax (define-make-disconnections stx)
  (syntax-case stx [:]
    [(_ reason)
     (with-syntax* ([(REASON ...) (map (λ [r] (datum->syntax #'reason r))
                                       (dynamic-require-for-syntax "../assignment/disconnection.rkt"
                                                                   (syntax-e (ssh-symid #'reason))))])
       #'(begin (define-make-disconnection REASON) ...))]))

(define-make-disconnections SSH-Disconnection-Reason)
