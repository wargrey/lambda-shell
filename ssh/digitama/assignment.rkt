#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))

(require "kex.rkt")
(require "userauth.rkt")
(require "service.rkt")
(require "connection/channel.rkt")

(require "message/name.rkt")
(require "algorithm/pkcs1/hash.rkt")

(require "../datatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-syntax (define-ssh-symbols stx)
  (syntax-case stx [:]
    [(_ TypeU #:as Type ([enum val] ...) #:fallback fallback)
     (with-syntax* ([$Type (ssh-symname #'TypeU)]
                    [#%Type (ssh-symid #'TypeU)]
                    [(name ...) (for/list ([<enum> (in-syntax #'(enum ...))]) (ssh-typename <enum>))]
                    [fbname (let ([<fbname> (ssh-typename #'fallback)])
                              (unless (memq (syntax-e <fbname>) (syntax->datum #'(name ...)))
                                (raise-syntax-error 'define-ssh-symbols (format "the fall back value is not a symbol of ~a" (syntax-e #'TypeU)) #'fallback))
                              <fbname>)])
       (syntax/loc stx
         (begin (define-type TypeU (U 'name ... 'enum ...))
                
                (define #%Type : (Pairof TypeU (Listof TypeU)) '(name ...))

                (define $Type : (case-> [-> (Pairof TypeU (Listof TypeU))] [Symbol -> Type] [Integer -> TypeU])
                  (case-lambda
                    [() #%Type]
                    [(v) (cond [(symbol? v) (case v [(enum name) val] ... [else ($Type 'fbname)])]
                               [else (case v [(val) 'name] ... [else 'fbname])])])))))]))

(define-syntax (define-ssh-name stx)
  (syntax-case stx [:]
    [(_ &database [name comments ... #:=> [data ...]])
     (syntax/loc stx (set-box! &database (cons (cons 'name (vector-immutable data ...)) (unbox &database))))]
    [(_ &database [name comments ... #:=> datum])
     (syntax/loc stx (set-box! &database (cons (cons 'name datum) (unbox &database))))]
    [(_ &database [name comments ...])
    (syntax/loc stx (void))]))

(define-syntax (define-ssh-namebase stx)
  (syntax-case stx [:]
    [(_ id : SSH-Type #:as Type)
    (with-syntax ([&id (format-id #'id "&~a" (syntax-e #'id))]
                  [$SSH-Type (format-id #'SSH-Type "$~a" (syntax-e #'SSH-Type))])
       (syntax/loc stx
         (begin (define-type SSH-Type Type)
                (define &id : (Boxof (Listof (Pairof Symbol SSH-Type))) (box null))
                
                (define id : (case-> [-> (Listof (Pairof Symbol SSH-Type))]
                                     [Boolean -> (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) -> (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) Boolean -> (Listof (Pairof Symbol SSH-Type))])
                  (case-lambda
                    [() (id #true)]
                    [(name-list none-last?) (ssh-filter-names name-list (unbox &id) none-last?)]
                    [(branch) (cond [(list? branch) (id branch #true)]
                                    [else (let ([base (unbox &id)])
                                            (ssh-filter-names (map (inst car Symbol SSH-Type) base)
                                                                   base branch))])]))

                (define $SSH-Type : (-> (Listof Symbol) (SSH-Name-Listof SSH-Type))
                  (lambda [name-list]
                    (define base : (Listof (Pairof Symbol SSH-Type)) (id))
                    (for/list : (SSH-Name-Listof SSH-Type) ([name (in-list name-list)])
                      (or (assq name base)
                          (cons name #false))))))))]))

(define-syntax (define-ssh-names stx)
  (syntax-case stx [:]
    [(_ #:kex (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-kex-algorithms definition) ...))]
    [(_ #:hostkey (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-hostkey-algorithms definition) ...))]
    [(_ #:cipher (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-cipher-algorithms definition) ...))]
    [(_ #:mac (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-mac-algorithms definition) ...))]
    [(_ #:compression (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-compression-algorithms definition) ...))]
    
    [(_ #:authentication (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-authentication-methods definition) ...))]
    [(_ #:service (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-registered-services definition) ...))]
    [(_ #:application (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-registered-applications definition) ...))]

    [(_ #:channel (definition ...))
     (syntax/loc stx (begin (define-ssh-name &ssh-registered-channels definition) ...))]
    
    [(_ keyword (definitions ...))
     (with-syntax* ([&id (let ([kw (syntax-e #'keyword)])
                           (unless (keyword? kw) (raise-syntax-error 'define-ssh-algorithms "expected a keyword" #'keyword))
                           (let ([&id (format-id #'keyword "&~a" (keyword->string kw))])
                             (unless (identifier-binding &id) (raise-syntax-error 'define-ssh-algorithms "unknown algorithm type" #'keyword))
                             &id))])
       (syntax/loc stx (begin (define-ssh-name &id definitions) ...)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-λCipher! (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index))
(define-type SSH-λCompression (->* (Bytes) (Natural Natural) Bytes))

(define-ssh-namebase ssh-kex-algorithms : SSH-Kex# #:as (Immutable-Vector SSH-Kex-Constructor (-> Bytes Bytes)))
(define-ssh-namebase ssh-hostkey-algorithms : SSH-Hostkey# #:as (Immutable-Vector SSH-Hostkey-Constructor PKCS#1-Hash))
(define-ssh-namebase ssh-compression-algorithms : SSH-Compression# #:as (Immutable-Vector (Option SSH-λCompression) (Option SSH-λCompression)))
(define-ssh-namebase ssh-cipher-algorithms : SSH-Cipher# #:as (Immutable-Vector (-> Bytes Bytes (Values SSH-λCipher! SSH-λCipher!)) Byte Byte))
(define-ssh-namebase ssh-mac-algorithms : SSH-MAC# #:as (Immutable-Vector (-> Bytes (->* (Bytes) (Natural Natural) Bytes)) Index))

(define-ssh-namebase ssh-authentication-methods : SSH-Authentication# #:as SSH-Userauth-Constructor)
(define-ssh-namebase ssh-registered-services : SSH-Service# #:as SSH-Service-Constructor)
(define-ssh-namebase ssh-registered-applications : SSH-Application# #:as SSH-Application-Constructor)

(define-ssh-namebase ssh-registered-channels : SSH-Channel# #:as SSH-Channel-Constructor)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-filter-names : (All (a) (-> (Listof Symbol) (Listof (Pairof Symbol a)) Boolean (Listof (Pairof Symbol a))))
  (lambda [name-list algbase none-last?]
    (define seman : (Listof Symbol)
      (cond [(not (and none-last? (memq 'none name-list))) (reverse name-list)]
            [else (cons 'none (reverse (remq* '(none) name-list)))]))
    
    (let filter ([algorithms : (Listof (Pairof Symbol a)) null]
                 [seman : (Listof Symbol) seman])
      (cond [(null? seman) algorithms]
            [else (let ([maybe (assq (car seman) algbase)]
                        [rest (cdr seman)])
                    (cond [(not maybe) (filter algorithms rest)]
                          [else (filter (cons maybe algorithms) rest)]))]))))
  