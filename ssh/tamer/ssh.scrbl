#lang scribble/manual

@(require "tamer.rkt")

@handbook-title/pkg-desc[]

The secure shell (@deftech{SSH}) Protocol is a protocol for secure remote login and other secure network services over an insecure network.

This document describes a full-featured client-side and server-side library named @deftech[the-name]
implementing the @tech{SSH} protocol that wrote in @bold{Typed Racket} along with minimal @bold{C} extensions.

@the-name does not reply on @cite{OpenSSH} and @cite{OpenSSL}, nor plan to stick with them.
They are referenced here for parts of their sources and interoperability tests.

@bold{Warning:} Meanwhile, @the-name is far away from @italic{full-featured} and may not work accurately.
Everything therefore is subject to change.

@tamer-smart-summary[]

@handbook-smart-table[]

@include-section{walkthrough.scrbl}
@include-section{asnder.scrbl}

@handbook-appendix[#:index? #true
 (rfc-bib-entry 4250 "The Secure Shell (SSH) Protocol Assigned Numbers" #:author "S. Lehtinen" #:date 2006 #:key 'SSH-NUMBERS)
 (rfc-bib-entry 4251 "The Secure Shell (SSH) Protocol Architecture"     #:author "T. Ylonen"   #:date 2006 #:key 'SSH-ARCH)
 (rfc-bib-entry 4252 "The Secure Shell (SSH) Authentication Protocol"   #:author "T. Ylonen"   #:date 2006 #:key 'SSH-USERAUTH)
 (rfc-bib-entry 4253 "The Secure Shell (SSH) Transport Layer Protocol"  #:author "T. Ylonen"   #:date 2006 #:key 'SSH-TRANS)
 (rfc-bib-entry 4254 "The Secure Shell (SSH) Connection Protocol"       #:author "T. Ylonen"   #:date 2006 #:key 'SSH-CONNECT)

 (bib-entry #:key    "OpenSSH"
            #:title  "OpenSSH: Keeping Your Communication Secret"
            #:author (org-author-name "OpenBSD Foundation")
            #:date   "2018"
            #:url    "https://www.openssh.com")
 
 (bib-entry #:key    "OpenSSL"
            #:title  "OpenSSH: Cryptography and SSL/TLS Toolkit"
            #:author (org-author-name "OpenSSL Software Foundation")
            #:date   "2019"
            #:url    "https://www.openssl.org")]
