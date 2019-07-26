#lang scribble/manual

@(require digimon/tamer)

@handbook-title/pkg-desc[]

The secure shell (@deftech{SSH}) Protocol is a protocol for secure remote login and other secure network services over an insecure network.

This document describes an eventually full-featured @tech{SSH} implementation that wrote in @bold{Typed Racket} with minimal @bold{C} extensions.


@;tamer-smart-summary[]

@handbook-smart-table[]

@include-section{walkthrough.scrbl}
@include-section{asnder.scrbl}

@handbook-appendix[#:index? #true
 (rfc-bib-entry 4250 "The Secure Shell (SSH) Protocol Assigned Numbers" #:author "S. Lehtinen" #:date 2006 #:key 'SSH-NUMBERS)
 (rfc-bib-entry 4251 "The Secure Shell (SSH) Protocol Architecture"     #:author "T. Ylonen"   #:date 2006 #:key 'SSH-ARCH)
 (rfc-bib-entry 4252 "The Secure Shell (SSH) Authentication Protocol"   #:author "T. Ylonen"   #:date 2006 #:key 'SSH-USERAUTH)
 (rfc-bib-entry 4253 "The Secure Shell (SSH) Transport Layer Protocol"  #:author "T. Ylonen"   #:date 2006 #:key 'SSH-TRANS)
 (rfc-bib-entry 4254 "The Secure Shell (SSH) Connection Protocol"       #:author "T. Ylonen"   #:date 2006 #:key 'SSH-CONNECT)]
