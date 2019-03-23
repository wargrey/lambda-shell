#lang typed/racket/base

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/string))

(require (for-syntax (only-in math/number-theory
                              prime?)))

(define-for-syntax (symbols->prime <hexadecimals>)
  (define <hexadecimal>s (syntax->list <hexadecimals>))
  (define hexadecimals
    (for/list ([<hex> (in-list <hexadecimal>s)])
      (define hex (syntax-e <hex>))
      (if (symbol? hex)
          (let ([subsym (symbol->string hex)])
            (or (and (string->number subsym 16) subsym)
                (raise-syntax-error 'symbols->prime "not a hexadecimal subsymbol" <hex>)))
          (if (integer? hex)
              (raise-syntax-error 'symbols->prime "numerical subsymbol, literalize it first" <hex>)
              (raise-syntax-error 'symbols->prime "not a numerical subsymbol" <hex>)))))
  
  (let ([p (string->number (apply string-append hexadecimals) 16)])
    (unless (prime? p)
      (raise-syntax-error
       'symbols->prime "not a prime number" #false #false <hexadecimal>s))
    
    (datum->syntax <hexadecimals> p)))

(define-syntax (make-prime stx)
  (syntax-case stx []
    [(_ hexadecimals ...)
     (with-syntax ([prefab-p (symbols->prime #'[hexadecimals ...])])
       #'prefab-p)]))

(define-syntax (define-prime stx)
  (syntax-case stx []
    [(_ p hexadecimals ...)
     #'(define p : Natural (make-prime hexadecimals ...))]))
