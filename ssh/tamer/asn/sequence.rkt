#lang scribble/lp2

@(require digimon/tamer)

@(define-bib MS-SEQ
   #:title    "DER Encoding of ASN.1 Types"
   #:author   (org-author-name "Microsoft")
   #:date     2018
   #:url      "https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-sequence")

@handbook-story{ASN.1 Sequence}

@;tamer-smart-summary[]

@handbook-scenario{Plain Sequence}

@tamer-action[
 (define-asn-sequence plain-seq : Plain-Seq
   ([name : asn-string/ia5 #:default "Smith"]
    [ok : asn-boolean #:optional]))
 (define octets (plain-seq->bytes (make-plain-seq #:ok #true)))
 (unsafe-bytes->plain-seq* octets)
 (bytes->hex-string octets #:separator " ")]

@handbook-scenario{Nested Sequence}

This example is defined in @~cite[MS-SEQ].

@bold{NOTE} Encoding @italic{BIT String} as primitive is required by @italic{DER}.

@tamer-action[
 (define-asn-sequence head : Head
   ([id : asn-oid]
    [sep : asn-null #:default (void)]))
 (define-asn-sequence body : Body
   ([n : asn-integer]
    [e : asn-integer #:default 65537]))
 (define-asn-sequence nested-seq : Nested-Seq
   ([head : head]
    [bitset : asn-bit-string]
    [body : body]))
 (define octets
   (let ([h (make-head #:id (list 1 2 840 113549 1 1 1))]
         [b (make-body #:n (random-odd-prime 1024))])
     (nested-seq->bytes (make-nested-seq #:head h #:bitset (cons #"" 0) #:body b))))
 (unsafe-bytes->nested-seq* octets)
 (asn-pretty-print octets)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<asn.1-der:sequence:*>|)]

@chunk[|<asn.1-der:sequence:*>|
       (module story typed/racket/base
         (require (submod digimon/tamer typed))
         
         <sequence>)]

@chunk[<sequence>
       (require "../../digitama/algorithm/random.rkt")
       (require "../../digitama/asn-der/primitive.rkt")
       (require "../../digitama/asn-der/sequence.rkt")
       (require "../../digitama/asn-der/pretty.rkt")]
