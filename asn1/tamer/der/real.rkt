#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN1bSW
   #:title    "ASN.1 by Simple Words"
   #:author   (authors "Yury Strozhevsky")
   #:date     2012
   #:url      "https://www.strozhevsky.com/free_docs/asn1_in_simple_words.pdf")

@handbook-story{ASN.1 Reals}

@italic{Flonum} is worth its own story although it is rare in cryptography.
Some details are learnt from @~cite[ASN1bSW].

@;tamer-smart-summary[]

@handbook-scenario{Special Real Values}

@tamer-action[
 (asn-primitive -inf.0)
 (asn-primitive -0.0)
 (asn-primitive +0.0)
 (asn-primitive +inf.0)
 (asn-primitive +nan.0)]

@handbook-scenario{Base 2 Representation}

@tamer-action[
 (default-asn-real-base 2)

 (asn-primitives simple-reals)
 (asn-primitives incommensurable-reals)
 (asn-primitives extreme-values)
 (asn-primitives random-values)]

@handbook-scenario{Base 8 Representation}

@tamer-action[
 (default-asn-real-base 8)

 (asn-primitives simple-reals)
 (asn-primitives incommensurable-reals)
 (asn-primitives extreme-values)
 (asn-primitives random-values)]

@handbook-scenario{Base 10 Representation}

@tamer-action[
 (default-asn-real-base 10)

 (asn-primitives simple-reals)
 (asn-primitives incommensurable-reals)
 (asn-primitives extreme-values)
 (asn-primitives random-values)]

@handbook-scenario{Base 16 Representation}

@tamer-action[
 (default-asn-real-base 16)

 (asn-primitives simple-reals)
 (asn-primitives incommensurable-reals)
 (code:comment "Note that decimal representation is the fallback for some small reals(TODO: why?)")
 (asn-primitives extreme-values)
 (asn-primitives random-values)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <primitive>)]

@chunk[<primitive>
       (require "../../digitama/der/base.rkt")
       (require "../../digitama/der/primitive.rkt")

       (require math/base)
       (require math/flonum)

       (define simple-reals (list 0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9 1.0 1.1 1.2 1.3 1.4 1.5 1.6))
       (define incommensurable-reals (list euler.0 pi gamma.0 phi.0 catalan.0))
       (define extreme-values (list epsilon.0 -max.0 -min.0 -max-subnormal.0 +max-subnormal.0 +max.0 +min.0))
       (define random-values (list -0.0015625 -15.625 (* +max.0 0.5) (+ (flexpt 2.0 81.0) epsilon.0)))

       (define asn-primitive
         (lambda [datum [identifier #false]]
           (define os (asn-primitive->bytes datum identifier))
           (define-values (restored _) (asn-bytes->primitive os))
           
           (if (equal? datum restored) ; `+nan.0`s cannot be compared with arithemtic operator. 
               (cons datum (bytes->hex-string os #:separator " "))
               (eprintf "~a[~a]: ~a~n" datum restored (bytes->hex-string os #:separator " ")))))

       (define asn-primitives
         (lambda [data]
           (filter-not void? (map asn-primitive data))))]
