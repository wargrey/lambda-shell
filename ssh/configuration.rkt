#lang typed/racket/base

(provide (except-out (all-defined-out) define-configuration))
(provide (rename-out [make-$ssh make-ssh-configuration]))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-syntax (define-configuration stx)
  (syntax-case stx [:]
    [(_ id : ID ([field : FieldType defval] ...))
     (with-syntax ([make-id (format-id #'id "make-~a" (syntax-e #'id))]
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
       #'(begin (struct id ([field : FieldType] ...) #:transparent #:type-name ID)

                (define default-ssh-parameter : (Parameterof FieldType) (make-parameter defval)) ...
                
                (define (make-id kw-args ...) : ID
                  (id (or field (default-ssh-parameter)) ...))))]))

(define-type SSH-Server-Line-Handler (-> String Void))
(define-type SSH-Debug-Message-Handler (-> Boolean String Symbol Void))

(define-configuration $ssh : SSH-Configuration
  ([protoversion : Positive-Flonum 2.0]
   [softwareversion : String ""]
   [comments : (Option String) #false]
   [longest-identification-length : Positive-Index 255]
   
   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   [payload-capacity : Index 32768]
   [minimum-key-bits : Positive-Index 3072]

   [timeout : (Option Nonnegative-Real) #false]
   [rekex-traffic : Positive-Integer (* 1024 1024 1024)]

   [debug-message-handler : SSH-Debug-Message-Handler void]

   [server-banner-handler : SSH-Server-Line-Handler void]
   [maximum-server-banner-count : Positive-Index 1024]
   [longest-server-banner-length : Positive-Index 8192]

   [pretty-log-packet-level : (Option Log-Level) #false]

   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   [userauth-timeout : Index 600]
   [userauth-retry : Index 20]))
