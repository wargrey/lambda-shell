#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690

(provide (all-defined-out))
(provide ASN-Bitset ASN-Object-Identifier ASN-Relative-Object-Identifier)

(require "base.rkt")
(require "octets.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-asn-primitive stx)
  (syntax-case stx [:]
    [(_ type #:as Type tag [asn-datum? asn->octets octets->asn] comments ...)
     (with-syntax* ([asn (format-id #'type "asn-~a" (syntax-e #'type))]
                    [asn->bytes (format-id #'asn "~a->bytes" (syntax-e #'asn))]
                    [unsafe-bytes->asn (format-id #'asn "unsafe-asn-bytes->~a" (syntax-e #'asn))]
                    [unsafe-bytes->asn* (format-id #'asn "unsafe-asn-bytes->~a*" (syntax-e #'asn))]
                    [ASN->type (format-id #'asn "~a" (gensym 'ASN->bytes:))])
       #'(begin (define asn : Byte (asn-identifier-octet tag #:class 'Universal #:constructed? #false))

                (define asn->bytes : (-> Type Bytes)
                  (let ([id (bytes asn)])
                    (lambda [self]
                      (let ([octets (asn->octets self)])
                        (bytes-append id (asn-length->octets (bytes-length octets)) octets)))))

                (define unsafe-bytes->asn : (->* (Bytes) (Natural) (Values Type Natural))
                  (lambda [basn [offset 0]]
                    (define-values (size content-offset) (asn-octets->length basn (+ offset 1)))
                    (define end : Natural (+ size content-offset))
                    
                    (values (octets->asn basn content-offset end)
                            end)))
                
                (define unsafe-bytes->asn* : (->* (Bytes) (Natural) Type)
                  (lambda [basn [offset 0]]
                    (define-values (datum end-index) (unsafe-bytes->asn basn offset))
                    datum))

                (define ASN->type : (-> ASN-Primitive (Option Bytes))
                  (lambda [self]
                    (and (asn-datum? self)
                         (asn->bytes self))))

                (hash-set! asn-type->bytes-database asn ASN->type)
                (hash-set! asn-bytes->type-database asn unsafe-bytes->asn)
                (hash-set! asn-type-metainfo-database 'asn '(Type asn->bytes unsafe-bytes->asn))))]))

(define-syntax (define-asn-primitives stx)
  (syntax-case stx [:]
    [(_ ASN-Primitive [type #:as Type tag [datum? interfaces ...]] ...)
     #'(begin (define-type ASN-Primitive (U EOF Type ...))
              
              (define-asn-primitive type #:as Type tag [datum? interfaces ...]) ...)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-type->bytes-database : (HashTable Byte (-> ASN-Primitive (Option Bytes))) (make-hasheq))
(define asn-bytes->type-database : (HashTable Byte (->* (Bytes) (Index) (Values ASN-Primitive Natural))) (make-hasheq))
(define asn-type-metainfo-database : (HashTable Symbol (List Symbol Symbol Symbol)) (make-hasheq))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-asn-primitives ASN-Primitive
  [boolean          #:as Boolean                        #x01 [boolean?                        asn-boolean->octets asn-octets->boolean]]
  [integer          #:as Integer                        #x02 [exact-integer?                  asn-integer->octets network-bytes->integer]]
  [bit-string       #:as ASN-Bitset                     #x03 [asn-bit-string?                 asn-bit-string->octets asn-octets->bit-string]]
  [octet-string     #:as Bytes                          #x04 [bytes?                          values subbytes]]
  
  [null             #:as Void                           #x05 [void?                           asn-null->octets void]]
  [oid              #:as ASN-Object-Identifier          #x06 [asn-object-identifier?          asn-oid->octets asn-octets->oid]]
  [relative-oid     #:as ASN-Relative-Object-Identifier #x0D [asn-relative-object-identifier? asn-relative-oid->octets asn-octets->relative-oid]]

  [string/utf8      #:as String                         #x0C [string?                         string->bytes/utf-8 asn-octets->string/utf8]]
  [string/printable #:as String                         #x13 [string?                         string->bytes/latin-1 asn-octets->string/printable]]
  [string/ia5       #:as String                         #x16 [string?                         string->bytes/latin-1 asn-octets->string/ia5]]
  [string/bmp       #:as String                         #x1E [string?                         asn-string->octets/bmp asn-octets->string/bmp]])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-primitive->bytes : (->* (ASN-Primitive) ((Option Byte)) Bytes)
  (lambda [self [maybe-id #false]]
    (or (if (byte? maybe-id)
            (let ([maybe-asn->types (hash-ref asn-type->bytes-database maybe-id (λ [] #false))])
              (and maybe-asn->types
                   (let ([maybe-octets (maybe-asn->types self)])
                     (and (bytes? maybe-octets) maybe-octets))))
            (let retry : (Option Bytes) ([asn->typeses : (Listof (-> ASN-Primitive (Option Bytes))) (hash-values asn-type->bytes-database)])
              (and (pair? asn->typeses)
                   (or ((car asn->typeses) self)
                       (retry (cdr asn->typeses))))))
        (bytes #x00 #x00) #| End of Content |#)))

(define asn-bytes->primitive : (->* (Bytes) (Index) (Values ASN-Primitive Natural))
  (lambda [basn [offset 0]]
    (define id : Byte (bytes-ref basn offset))
    (define maybe-types->asn : (Option (->* (Bytes) (Index) (Values ASN-Primitive Natural))) (hash-ref asn-bytes->type-database id (λ [] #false)))

    (cond [(and maybe-types->asn) (maybe-types->asn basn offset)]
          [else (values eof (assert offset index?))])))
