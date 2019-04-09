#lang scribble/lp2

@(require digimon/tamer)

@(define-bib MS-SEQ
   #:title    "DER Encoding of ASN.1 Types"
   #:author   (org-author-name "Microsoft")
   #:date     2018
   #:url      "https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-sequence")

@handbook-story{ASN.1 Sequence and Sequence-Of}

@;tamer-smart-summary[]

@handbook-scenario{Sequences}

@tamer-action[
 (define-asn-sequence plain-seq : Plain-Seq
   ([name : asn-string/ia5 #:default "Smith"]
    [ok : asn-boolean]))
 (define plain-octets (plain-seq->bytes (make-plain-seq #:ok #true)))
 (unsafe-bytes->plain-seq* plain-octets)
 (asn-pretty-print plain-octets)]

This example is defined in @~cite[MS-SEQ].

@bold{NOTE} Encoding @italic{bitstring} as primitive is required by @italic{DER}.

@tamer-action[
 (define-asn-sequence head : Head
   ([id : asn-oid]
    [sep : asn-null #:default (void)]))
 (define-asn-sequence body : Body
   ([n : asn-integer]
    [e : asn-integer #:default 65537]))
 (define-asn-sequence nested-seq : Nested-Seq
   ([head : Head]
    [bitset : asn-bitstring]
    [body : body]))
 (define nested-octets
   (let ([h (make-head #:id (list 1 2 840 113549 1 1 1))]
         [b (make-body #:n (random-odd-prime 1024))])
     (nested-seq->bytes (make-nested-seq #:head h #:bitset (cons #"" 0) #:body b))))
 (unsafe-bytes->nested-seq* nested-octets)
 (asn-pretty-print nested-octets)]

@handbook-scenario{Sequence with Optional Components}

@tamer-action[
 (define-asn-sequence option-seq : Option-Seq
   ([name : asn-string/printable]
    [partner : asn-string/printable #:optional]
    [seq : asn-integer #:default 3]))
 (define no-partner-octets (option-seq->bytes (make-option-seq #:name "wargrey" #:seq 0)))
 (define partner-octets (option-seq->bytes (make-option-seq #:name "Sakuyamon" #:partner "Rika Nonaka")))
 (asn-pretty-print no-partner-octets)
 (asn-pretty-print partner-octets)]

@handbook-scenario{Sequence-Ofs}

@tamer-action[
 (define-asn-sequence seq-of : SeqOf #:of Option-Seq)
 (unsafe-bytes->seq-of*
  (seq-of->bytes (list (unsafe-bytes->option-seq* no-partner-octets)
                       (unsafe-bytes->option-seq* partner-octets))))]

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
