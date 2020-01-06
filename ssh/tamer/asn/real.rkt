#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN.1bSW
   #:title    "ASN.1 by Simple Words"
   #:author   (authors "Yury Strozhevsky")
   #:date     2012
   #:url      "https://www.strozhevsky.com/free_docs/asn1_in_simple_words.pdf")

@handbook-story{ASN.1 Reals}

@italic{Flonum} is worth its own story although it is rare in cryptography.
The algorithm was inspired by @~cite[ASN.1bSW].

@;tamer-smart-summary[]

@handbook-scenario{Special Real Values}

@tamer-action[
 (asn-primitive -inf.0)
 (asn-primitive -0.0)
 (asn-primitive +0.0)
 (asn-primitive +inf.0)
 (asn-primitive +nan.0)]

@handbook-scenario{Simple Real Values}

@tamer-action[
 (asn-primitive 0.15625)
 
 (parameterize ([default-asn-real-base 8])
   (asn-primitive 0.15625))
 
 (parameterize ([default-asn-real-base 10])
   (asn-primitive 0.15625))
 
 (parameterize ([default-asn-real-base 16])
   (asn-primitive 0.15625))]

@handbook-scenario{Incommensurable Values}

@tamer-action[
 (asn-primitive euler.0)
 (asn-primitive pi)
 (asn-primitive gamma.0)
 (asn-primitive phi.0)
 (asn-primitive catalan.0)]

@handbook-scenario{Extreme Values}

@tamer-action[
 (asn-primitive epsilon.0)
 (asn-primitive -max.0)
 (asn-primitive -min.0)
 (asn-primitive +max.0)
 (asn-primitive +min.0)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <primitive>)]

@chunk[<primitive>
       (require "../../digitama/asn-der/base.rkt")
       (require "../../digitama/asn-der/primitive.rkt")

       (require math/base)
       (require math/flonum)

       (define asn-primitive
         (lambda [datum [identifier #false]]
           (printf "flonum: ~a~n" datum)

           (define os (asn-primitive->bytes datum identifier))
           (define-values (restored _) (asn-bytes->primitive os))
           
           (if (equal? datum restored)
               (values (bytes->bin-string os #:separator " ")
                       (bytes->hex-string os #:separator " "))
               (eprintf "~a~n" (bytes->hex-string os #:separator " ")))))]
