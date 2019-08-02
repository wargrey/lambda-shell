#lang typed/racket/base

(provide (except-out (all-defined-out) define-make-channel-failure define-make-channel-failures))

(require "name.rkt")
(require "../message/connection.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

;; NOTE
; Macros that defined in typed racket cannot be used in untyped environment directly,
; so that `dynamic-require-for-syntax` is used here to surpass the problem.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-syntax (define-make-channel-failure stx)
  (syntax-case stx [:]
    [(_ REASON)
     (with-syntax* ([make-id (format-id #'REASON "make-~a" (syntax-e (ssh-typeid #'REASON)))]
                    [make+id (format-id #'REASON "make+~a" (syntax-e (ssh-typeid #'REASON)))])
       #'(define make-id : (->* (Index) ((Option String) #:language (Option Symbol) #:source (Option Procedure)) #:rest Any SSH-MSG-CHANNEL-OPEN-FAILURE)
           (lambda [recipient #:language [lang #false] #:source [src #false] [descfmt #false] . argl]
             (let* ([desc (and descfmt (apply format descfmt argl))]
                    [desc (and desc (if (and src) (format "~a: ~a" (object-name src) desc) desc))])
               (make-ssh:msg:channel:open:failure #:recipient recipient #:reason 'REASON #:description desc #:language lang)))))]))

(define-syntax (define-make-channel-failures stx)
  (syntax-case stx [:]
    [(_ reason)
     (with-syntax* ([(REASON ...) (map (λ [r] (datum->syntax #'reason r))
                                       (dynamic-require-for-syntax "../assignment/connection.rkt"
                                                                   (syntax-e (ssh-symid #'reason))))])
       #'(begin (define-make-channel-failure REASON) ...))]))

(define-make-channel-failures SSH-Channel-Failure-Reason)
