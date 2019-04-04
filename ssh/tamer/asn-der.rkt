#lang scribble/lp2

@(require digimon/tamer)

@(define-bib ASN.1-DER
   #:title    "The ASN.1 Distinguished Encoding Rules"
   #:author   (org-author-name "ITU-T")
   #:date     2015
   #:url      "https://www.itu.int/rec/T-REC-X.690-201508-I/en")

@(define-bib asn1-lib
   #:title    "ASN.1"
   #:author   (authors "Ryan Culpepper")
   #:date     2018
   #:url      "https://github.com/rmculpepper/asn1/blob/master/asn1-test/basic.rkt")

@handbook-story{ASN.1 Distinguished Encoding Rules}

This section demonstrates the implementation of @~cite[ASN.1-DER].

@;tamer-smart-summary[]

@handbook-scenario{Basic Encoding Rules}

@tamer-action[
 (asn-length 127)
 (asn-length 201)
 (asn-length 435)]

@tamer-action[
 (asn-encode make-asn-boolean #true)
 (asn-encode make-asn-boolean #false)]

These testcases for ASN.1 Integer are defined in @~cite[asn1-lib].
@tamer-action[
 (asn-encode make-asn-integer 0)
 (asn-encode make-asn-integer 1)
 (asn-encode make-asn-integer -1)
 (asn-encode make-asn-integer 127)
 (asn-encode make-asn-integer -127)
 (asn-encode make-asn-integer 128)
 (asn-encode make-asn-integer -128)
 (asn-encode make-asn-integer 255)
 (asn-encode make-asn-integer 256)
 (asn-encode make-asn-integer (expt 17 80))
 (asn-encode make-asn-integer (- (expt 23 81)))]

@tamer-action[
 (asn-encode make-asn-oid '(1 3 6 1 4 1 311 21 20))
 #;(asn-encode make-asn-oid '(2 999 3) #|3, 0x883703|#)
 (asn-encode make-asn-relative-oid '(8571 3 2) #|4, 0xC27B0302|#)]

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
       (require "../digitama/asn-der/primitive.rkt")
       
       (define asn-length
         (lambda [length]
           (define os (asn-length->octets length))
           (define-values (restored _) (asn-octets->length os))
           (cons restored (bytes->bin-string os #:separator " "))))

       (define asn-encode
         (lambda [make-asn datum]
           (define os (asn-type->bytes (make-asn datum)))
           (define-values (restored _) (asn-bytes->type os))
           (values restored
                   (bytes->bin-string os #:separator " ")
                   (bytes->hex-string os #:separator " "))))]
