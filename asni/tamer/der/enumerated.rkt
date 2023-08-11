#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN.1-CbHS
   #:title   "ASN.1: Communication between Heterogeneous Systems"
   #:author  (authors "Olivier Dubuisson")
   #:date    2000)

@handbook-story{ASN.1 Enumerated Values}

The definition of @italic{Enumerated} value can be found in @cite{X680},
and examples can be found in @~cite[ASN.1-CbHS].

@;tamer-smart-summary[]

@handbook-scenario{Root Enumerations}

@tamer-repl[
 (define-asn-enumerated auto-index : Auto-Index #:+ Byte
   (1st 3rd [2nd 2] 4th [zero 0] [infinite 255]))
 
 (for/list : (Listof (Pairof Auto-Index Byte)) ([id (in-list (auto-index))])
   (cons id (auto-index id)))

 ((inst asn-primitive Auto-Index) 'zero auto-index->bytes unsafe-bytes->auto-index*)
 ((inst asn-primitive Auto-Index) 'infinite auto-index->bytes unsafe-bytes->auto-index*)]

@handbook-scenario{Additional Enumerations}

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module tamer typed/racket
         (require digimon/format)
         <enumeratoin>)]

@chunk[<enumeratoin>
       (require "../../digitama/der/primitive.rkt")
       (require "../../digitama/der/enumerated.rkt")

       (define asn-primitive : (All (e) (-> e (-> e Bytes) (-> Bytes e) (U String Void)))
         (lambda [datum enum->bytes bytes->enum]
           (define os (enum->bytes datum))
           (define restored (bytes->enum os))
           
           (if (equal? datum restored)
               (bytes->hexstring os #:separator " ")
               (eprintf "~a~n" (bytes->hexstring os #:separator " ")))))]
