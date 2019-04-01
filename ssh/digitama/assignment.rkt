#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))

(require "kex.rkt")
(require "message.rkt")
(require "algorithm/pkcs/hash.rkt")

(require "../datatype.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))
(require (for-syntax racket/sequence))

(define-syntax (define-ssh-symbols stx)
  (syntax-case stx [:]
    [(_ TypeU : Type ([enum val] ...))
     (with-syntax ([$id (format-id #'TypeU "$~a" (syntax-e #'TypeU))]
                   [(name ...) (for/list ([<enum> (in-syntax #'(enum ...))]) (ssh-typename <enum>))])
       #'(begin (define-type TypeU (U 'name ... 'enum ...))
                (define $id : (case-> [Symbol -> Type] [Integer -> TypeU])
                  (λ [v] (cond [(symbol? v) (case v [(enum name) val] ... [else 0])]
                               [else (case v [(val) 'name] ... [else (error 'TypeU "unrecognized assignment: ~a" v)])])))))]))

(define-syntax (define-ssh-algorithm stx)
  (syntax-case stx [:]
    [(_ &database ([name comments ... #:=> [data ...]]))
     #'(set-box! &database (cons (cons 'name (vector-immutable data ...)) (unbox &database)))]
    [(_ &database ([name comments ... #:=> datum]))
     #'(set-box! &database (cons (cons 'name datum) (unbox &database)))]
    [(_ &database ([name comments ...]))
    #'(void)]))

(define-syntax (define-ssh-algorithm-database stx)
  (syntax-case stx [:]
    [(_ id : SSH-Type #:as Type)
     (with-syntax ([&id (format-id #'id "&~a" (syntax-e #'id))]
                   [$SSH-Type (format-id #'SSH-Type "$~a" (syntax-e #'SSH-Type))])
       #'(begin (define-type SSH-Type Type)
                
                (define &id : (Boxof (Listof (Pairof Symbol SSH-Type))) (box null))
                
                (define id : (case-> [-> (Listof (Pairof Symbol SSH-Type))]
                                     [(Listof Symbol) -> (Listof (Pairof Symbol SSH-Type))])
                  (case-lambda
                    [() (reverse (unbox &id))]
                    [(name-list) (let ([base (id)])
                                   (let filter ([algorithms : (Listof (Pairof Symbol SSH-Type)) null]
                                                [seman : (Listof Symbol) (reverse name-list)])
                                     (cond [(null? seman) algorithms]
                                           [else (let ([maybe (assq (car seman) base)]
                                                       [rest (cdr seman)])
                                                   (cond [(not maybe) (filter algorithms rest)]
                                                         [else (filter (cons maybe algorithms) rest)]))])))]))

                (define $SSH-Type : (-> (Listof Symbol) (SSH-Algorithm-Listof SSH-Type))
                  (lambda [name-list]
                    (define base : (Listof (Pairof Symbol SSH-Type)) (id))
                    (for/list : (SSH-Algorithm-Listof SSH-Type) ([name (in-list name-list)])
                      (or (assq name base)
                          (cons name #false)))))))]))

(define-syntax (define-ssh-algorithms stx)
  (syntax-case stx [:]
    [(_ #:kex (definition ...))
     #'(begin (define-ssh-algorithm &ssh-kex-algorithms (definition)) ...)]
    [(_ #:hostkey (definition ...))
     #'(begin (define-ssh-algorithm &ssh-hostkey-algorithms (definition)) ...)]
    [(_ #:cipher (definition ...))
     #'(begin (define-ssh-algorithm &ssh-cipher-algorithms (definition)) ...)]
    [(_ #:hmac (definition ...))
     #'(begin (define-ssh-algorithm &ssh-hmac-algorithms (definition)) ...)]
    [(_ #:compression (definition ...))
     #'(begin (define-ssh-algorithm &ssh-compression-algorithms (definition)) ...)]
    [(_ keyword (definitions ...)) (raise-syntax-error 'define-ssh-algorithm "unexpected algorithm type, expected #:hmac, #:cipher, or #:compression" #'keyword)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-package-algorithms
  ([cipher : (Pairof Symbol SSH-Cipher)]
   [mac : (Pairof Symbol SSH-HMAC)]
   [compression : (Pairof Symbol SSH-Compression)])
  #:transparent
  #:type-name SSH-Package-Algorithms)

(define-ssh-algorithm-database ssh-kex-algorithms : SSH-Kex #:as (Immutable-Vector SSH-Key-Exchange<%> (-> Bytes Bytes)))
(define-ssh-algorithm-database ssh-hostkey-algorithms : SSH-HostKey #:as (Immutable-Vector SSH-Host-Key<%> PKCS#1-Hash))
(define-ssh-algorithm-database ssh-cipher-algorithms : SSH-Cipher #:as (-> Bytes Bytes))
(define-ssh-algorithm-database ssh-hmac-algorithms : SSH-HMAC #:as (Immutable-Vector (-> Bytes Bytes Bytes) Index))
(define-ssh-algorithm-database ssh-compression-algorithms : SSH-Compression #:as (-> Bytes Bytes))
