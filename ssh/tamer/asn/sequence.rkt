#lang scribble/lp2

@(require digimon/tamer)

@(define-bib RFC-PKCS#1
   #:title    "RSASSA-PKCS-v1_5"
   #:author   (org-author-name "RFC8017")
   #:date     2016
   #:url      "https://tools.ietf.org/html/rfc8017#appendix-A.2.4")

@handbook-story{ASN.1 Sequence and Sequence-Of}

@;tamer-smart-summary[]

@handbook-scenario{Sequences}

@tamer-action[
 (define-asn-sequence plain-seq : Plain-Seq
   ([name : asn-string/ia5]
    [ok : asn-boolean]))
 (define plain-octets (plain-seq->bytes (make-plain-seq #:name "Smith" #:ok #true)))
 (unsafe-bytes->plain-seq* plain-octets)
 (asn-pretty-print plain-octets)]

The next example is defined int @~cite[RFC-PKCS#1].

@tamer-action[
 (define-asn-sequence digest-algorithm : Digest-Algorithm
   ([id : asn-oid]
    [parameter : asn-null #:default (void)]))
 (define-asn-sequence digest-info : Digest-Info
   ([algorithm : Digest-Algorithm]
    [digest : asn-octetstring]))
 
 (define sha1-octets
   (let ([id-sha (make-digest-algorithm #:id (list 1 3 14 3 2 26))])
     (digest-info->bytes (make-digest-info #:algorithm id-sha #:digest (sha1-bytes #"EMSA-PKCS1-v1_5")))))
 (unsafe-bytes->digest-info* sha1-octets)
 (asn-pretty-print sha1-octets)

 (define sha256-octets
   (let ([id-sha (make-digest-algorithm #:id (list 2 16 840 1 101 3 4 2 1))])
     (digest-info->bytes (make-digest-info #:algorithm id-sha #:digest (sha256-bytes #"EMSA-PKCS1-v1_5")))))
 (unsafe-bytes->digest-info* sha256-octets)
 (asn-pretty-print sha256-octets)]

@handbook-scenario{Sequences with Optional Components}

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
       (require "../../digitama/asn-der/sequence.rkt")
       (require "../../digitama/asn-der/pretty.rkt")]
