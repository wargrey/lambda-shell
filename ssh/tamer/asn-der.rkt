#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN.1-DER
   #:title    "The ASN.1 Distinguished Encoding Rules"
   #:author   (org-author-name "ITU-T")
   #:date     2015
   #:url      "https://www.itu.int/rec/T-REC-X.690-201508-I/en")

@handbook-story{ASN.1 Distinguished Encoding Rules}

This section demonstrates the implementation of @~cite[ASN.1-DER].

@;tamer-smart-summary[]

@handbook-scenario{Basic Encoding Rules}

@tamer-action[
 (asn-length 127)
 (asn-length 201)
 (asn-length 435)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<asn.1-der:*>|)]

@chunk[|<asn.1-der:*>|
       (module+ story
         <datatype>)]

@chunk[<datatype>
       (require "../digitama/asn-der/base.rkt")
       
       (define asn-length
         (lambda [length]
           (define os (asn-length->octets length))
           (define-values (restored _) (asn-octets->length os))
           (cons restored (bytes->bin-string os #:separator " "))))]
