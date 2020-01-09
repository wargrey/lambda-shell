#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN.1-CbHS
   #:title   "ASN.1: Communication between Heterogeneous Systems"
   #:author  (authors "Olivier Dubuisson")
   #:date    2000)

@handbook-story{ASN.1 Enumeration}

The definition of @bold{Enumerated} value can be found in @cite{X680},
and examples can be found in @~cite[ASN.1-CbHS].

@;tamer-smart-summary[]

@handbook-scenario{Root Enumerations}

@handbook-scenario{Additional Enumerations}

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module tamer typed/racket
         <enumeratoin>)]

@chunk[<enumeratoin>
       (require "../../digitama/der/enumeration.rkt")]
