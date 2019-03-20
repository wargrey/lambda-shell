#lang typed/racket/base

(provide (except-out (all-defined-out) define-option))

(require (for-syntax racket/base))
(require (for-syntax racket/string))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-syntax (define-option stx)
  (syntax-case stx [:]
    [(_ id : SSH-Option ([field : FieldType defval] ...))
     (with-syntax* ([make-id (format-id #'id "make-~a" (syntax-e #'id))]
                    [([kw-args ...] [default-ssh-parameter ...])
                     (let-values ([(args sarap)
                                   (for/fold ([args null] [sarap null])
                                             ([<field> (in-syntax #'(field ...))]
                                              [<FiledType> (in-syntax #'(FieldType ...))])
                                     (define <param> (datum->syntax <field> (string->symbol (format "default-ssh-~a" (syntax-e <field>)))))
                                     (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))      
                                     (values (cons <kw-name> (cons #`[#,<field> : (Option #,<FiledType>) #false] args))
                                             (cons <param> sarap)))])
                       (list args (reverse sarap)))])
       #'(begin (define-type SSH-Option id)
                
                (struct id ([field : FieldType] ...) #:transparent)

                (define default-ssh-parameter : (Parameterof FieldType) (make-parameter defval)) ...
                
                (define (make-id kw-args ...) : SSH-Option
                  (ssh-option (or field (default-ssh-parameter)) ...))))]))

(define-option ssh-option : SSH-Option
  ([protoversion : Positive-Flonum 2.0]
   [softwareversion : String ""]
   [comments : (Option String) #false]
   [payload-capacity : Index 32768]
   [timeout : (Option Nonnegative-Real) #false]))
