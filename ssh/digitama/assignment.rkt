#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))

(require "kex.rkt")
(require "message.rkt")
(require "userauth.rkt")
(require "channel.rkt")

(require "algorithm/pkcs1/hash.rkt")

(require "../datatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-syntax (define-ssh-symbols stx)
  (syntax-case stx [:]
    [(_ TypeU : Type ([enum val] ...))
     (with-syntax ([$id (format-id #'TypeU "$~a" (syntax-e #'TypeU))]
                   [id? (format-id #'TypeU "~a?" (syntax-e #'TypeU))]
                   [(name ...) (for/list ([<enum> (in-syntax #'(enum ...))]) (ssh-typename <enum>))])
       #'(begin (define-type TypeU (U 'name ... 'enum ...))

                (define $id : (case-> [Symbol -> Type] [Integer -> TypeU])
                  (λ [v] (cond [(symbol? v) (case v [(enum name) val] ... [else 0])]
                               [else (case v [(val) 'name] ... [else (error 'TypeU "unrecognized assignment: ~a" v)])])))

                (define id? : (-> Any Boolean : TypeU)
                  (λ [v] (cond [(or (eq? v 'name) (eq? v 'enum)) #true] ...
                               [else #false])))))]))

(define-syntax (define-ssh-algorithm stx)
  (syntax-case stx [:]
    [(_ &database [name comments ... #:=> [data ...]])
     #'(set-box! &database (cons (cons 'name (vector-immutable data ...)) (unbox &database)))]
    [(_ &database [name comments ... #:=> datum])
     #'(set-box! &database (cons (cons 'name datum) (unbox &database)))]
    [(_ &database [name comments ...])
    #'(void)]))

(define-syntax (define-ssh-algorithm-database stx)
  (syntax-case stx [:]
    [(_ id : SSH-Type #:as Type)
    (with-syntax ([&id (format-id #'id "&~a" (syntax-e #'id))]
                  [$SSH-Type (format-id #'SSH-Type "$~a" (syntax-e #'SSH-Type))])
       #'(begin (define-type SSH-Type Type)
                (define &id : (Boxof (Listof (Pairof Symbol SSH-Type))) (box null))
                
                (define id : (case-> [-> (Listof (Pairof Symbol SSH-Type))]
                                     [-> Boolean (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) -> (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) Boolean -> (Listof (Pairof Symbol SSH-Type))])
                  (case-lambda
                    [() (id #true)]
                    [(name-list none-last?) (ssh-filter-algorithms name-list (unbox &id) none-last?)]
                    [(branch) (cond [(list? branch) (id branch #true)]
                                    [else (let ([base (unbox &id)])
                                            (ssh-filter-algorithms (map (inst car Symbol SSH-Type) base)
                                                                   base branch))])]))

                (define $SSH-Type : (-> (Listof Symbol) (SSH-Algorithm-Listof SSH-Type))
                  (lambda [name-list]
                    (define base : (Listof (Pairof Symbol SSH-Type)) (id))
                    (for/list : (SSH-Algorithm-Listof SSH-Type) ([name (in-list name-list)])
                      (or (assq name base)
                          (cons name #false)))))))]))

(define-syntax (define-ssh-algorithms stx)
  (syntax-case stx [:]
    [(_ #:kex (definition ...))
     #'(begin (define-ssh-algorithm &ssh-kex-algorithms definition) ...)]
    [(_ #:hostkey (definition ...))
     #'(begin (define-ssh-algorithm &ssh-hostkey-algorithms definition) ...)]
    [(_ #:cipher (definition ...))
     #'(begin (define-ssh-algorithm &ssh-cipher-algorithms definition) ...)]
    [(_ #:mac (definition ...))
     #'(begin (define-ssh-algorithm &ssh-mac-algorithms definition) ...)]
    [(_ #:compression (definition ...))
     #'(begin (define-ssh-algorithm &ssh-compression-algorithms definition) ...)]
    [(_ #:authentication (definition ...))
     #'(begin (define-ssh-algorithm &ssh-authentication-methods definition) ...)]
    [(_ keyword (definitions ...)) (raise-syntax-error 'define-ssh-algorithm
                                                       "unexpected algorithm type, expected #:mac, #:cipher, #:compression, or #:authentication"
                                                       #'keyword)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-λCipher! (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index))
(define-type SSH-λCompression (->* (Bytes) (Natural Natural) Bytes))

(define-ssh-algorithm-database ssh-kex-algorithms : SSH-Kex# #:as (Immutable-Vector SSH-Kex-Constructor (-> Bytes Bytes)))
(define-ssh-algorithm-database ssh-hostkey-algorithms : SSH-Hostkey# #:as (Immutable-Vector SSH-Hostkey-Constructor PKCS#1-Hash))
(define-ssh-algorithm-database ssh-compression-algorithms : SSH-Compression# #:as (Immutable-Vector (Option SSH-λCompression) (Option SSH-λCompression)))
(define-ssh-algorithm-database ssh-cipher-algorithms : SSH-Cipher# #:as (Immutable-Vector (-> Bytes Bytes (Values SSH-λCipher! SSH-λCipher!)) Byte Byte))
(define-ssh-algorithm-database ssh-mac-algorithms : SSH-MAC# #:as (Immutable-Vector (-> Bytes (->* (Bytes) (Natural Natural) Bytes)) Index))

(define-ssh-algorithm-database ssh-authentication-methods : SSH-Authentication# #:as SSH-Userauth-Constructor)
(define-ssh-algorithm-database ssh-channel-constructors : SSH-Channel# #:as SSH-Channel-Constructor)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-filter-algorithms : (All (a) (-> (Listof Symbol) (Listof (Pairof Symbol a)) Boolean (Listof (Pairof Symbol a))))
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
  