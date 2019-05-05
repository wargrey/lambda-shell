#lang scribble/lp2

@(require digimon/tamer)

@(define-bib SSH-USERAUTH
   #:title  "The Secure Shell Authentication Protocol"
   #:author (org-author-name "RFC4252")
   #:date   2006
   #:url    "https://tools.ietf.org/html/rfc4252")

@handbook-story{The Secure Shell Authentication Protocol}

This section demonstrates the implementation of @~cite[SSH-USERAUTH].

@;tamer-smart-summary[]

@handbook-scenario{Authentication Requests}

@tamer-action[
 (ssh-message (make-ssh:msg:userauth:request #:username 'wargrey #:method 'none))
 (ssh-message (make-ssh:msg:userauth:request:publickey #:username 'wargrey #:algorithm "algorithm" #:blob "blob"))
 (define-values (octets adequate-request) (ssh-message (make-ssh:msg:userauth:request:publickey$ #:username 'wargrey #:signature "signature" #:algorithm "algorithm" #:blob "blob")))
 (values octets adequate-request)
 (ssh:msg:userauth:request? adequate-request)
 (ssh:msg:userauth:request:publickey? adequate-request)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<authentication:*>|)]

@chunk[|<authentication:*>|
       (module+ story
         <request>)]

@chunk[<request>
       (require "message.rkt")

       (require "../message.rkt")
       (require "../digitama/authentication/publickey.rkt")]
