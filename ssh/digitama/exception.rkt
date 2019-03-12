#lang typed/racket/base

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

#;(define-syntax (define-ssh-error stx)
  (syntax-case stx []
    [(_ exn:ssh #:as SSH-Error [subexn #:-> parent] ...)
     (with-syntax ([([make-exn make+exn throw-exn] ...)
                    (for/list ([<exn> (in-list (syntax->list #'(subexn ...)))])
                      (list (format-id <exn> "make-~a" (syntax-e <exn>))
                            (format-id <exn> "make+~a" (syntax-e <exn>))
                            (format-id <exn> "throw-~a" (syntax-e <exn>))))])
       #'(begin (define-type SSH-Error exn:ssh)
                (struct exn:ssh exn:fail ())
                (struct subexn parent ()) ...

                (define make-exn : (-> (U CSS-Syntax-Any (Listof CSS-Token)) CSS-Syntax-Error)
                  (lambda [v]
                    (css-make-syntax-error subexn v)))
                ...

                (define make+exn : (->* ((U CSS-Syntax-Any (Listof CSS-Token))) ((Option CSS:Ident) Log-Level) CSS-Syntax-Error)
                  (lambda [v [property #false] [level 'warning]]
                    (define errobj : CSS-Syntax-Error (css-make-syntax-error subexn v))
                    (css-log-syntax-error errobj property level)
                    errobj))
                ...

                (define throw-exn : (->* ((U CSS-Syntax-Any (Listof CSS-Token))) ((Option CSS:Ident) Log-Level) Nothing)
                  (lambda [v [property #false] [level 'warning]]
                    (raise (make+exn v property level))))
                ...))]))

(define throw-timeout-error : (->* (Symbol) (String) Void)
  (lambda [func [message "timeout"]]
    (call-with-escape-continuation
        (λ [[ec : Procedure]]
          (raise (make-exn:break (format "~a: ~a" func message)
                                 (current-continuation-marks)
                                 ec))))))
