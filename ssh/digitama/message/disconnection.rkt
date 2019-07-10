#lang typed/racket/base

(provide (except-out (all-defined-out) define-make-disconnection define-make-disconnections))

(require "name.rkt")
(require "../diagnostics.rkt")
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
     (with-syntax* ([make-id (format-id #'REASON "make-~a" (syntax-e (ssh-typeid #'REASON)))]
                    [make+id (format-id #'REASON "make+~a" (syntax-e (ssh-typeid #'REASON)))])
       #'(define make-id : (->* () ((Option String) #:language (U Symbol Void) #:source (Option Procedure)) #:rest Any SSH-MSG-DISCONNECT)
           (lambda [#:language [lang #false] #:source [src #false] [descfmt #false] . argl]
             (let* ([desc (unless (not descfmt) (if (null? argl) descfmt (apply format descfmt argl)))]
                    [desc (unless (not desc) (if (and src) (format "~a: ~a" (object-name src) desc) desc))])
               (make-ssh:msg:disconnect #:reason 'REASON #:language (or lang (void)) #:description desc)))))]))

(define-syntax (define-make-disconnections stx)
  (syntax-case stx [:]
    [(_ reason)
     (with-syntax* ([(REASON ...) (map (λ [r] (datum->syntax #'reason r))
                                       (dynamic-require-for-syntax "../assignment/disconnection.rkt"
                                                                   (syntax-e (ssh-symid #'reason))))])
       #'(begin (define-make-disconnection REASON) ...))]))

(define-make-disconnections SSH-Disconnection-Reason)
