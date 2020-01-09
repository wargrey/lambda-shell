#lang scribble/manual

@(require digimon/tamer)

@handbook-title/pkg-desc[]

@;tamer-smart-summary[]

@handbook-smart-table[]

@include-section{der.scrbl}

@handbook-appendix[#:index? #true
 (bib-entry #:key    "X680"
            #:title  "Information technology – Abstract Syntax Notation One (ASN.1): Specification of basic notation"
            #:author (org-author-name "ITU-T")
            #:date   "2015"
            #:url    "https://www.itu.int/rec/T-REC-X.680-201508-I/en")
 
 (bib-entry #:key    "X690"
            #:title  "Information technology – ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
            #:author (org-author-name "ITU-T")
            #:date   "2015"
            #:url    "https://www.itu.int/rec/T-REC-X.690-201508-I/en")]
