#lang scribble/lp2

@(require digimon/tamer)

@(define-bib SSH:TLP
   #:title    "The Secure Shell Transport Layer Protocol"
   #:author   (org-author-name "RFC4253")
   #:date     2006
   #:url      "https://tools.ietf.org/html/rfc4253")

@handbook-story{The Secure Shell Transport Layer Protocol}

This section demonstrates the implementation of @~cite[SSH:TLP].

@;tamer-smart-summary[]

@handbook-scenario{Identification String}

@tamer-action[
 default-identification
 (peer-identification default-identification)]

@tamer-action[
 (peer-identification "SSL-2.0-Bad_Prefix")
 (peer-identification "SSH-1.b-Bad_Protocol")
 (peer-identification "SSH-2.0--")
 (peer-identification (~a "SSH-2.0-tl_dr " (make-string SSH-LONGEST-IDENTIFICATION-LENGTH #\.)))]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<transport:*>|)]

@chunk[|<transport:*>|
       (module+ story
         <identification>)]

@chunk[<identification>
       (require "../digitama/transport/identification.rkt")

       (define-values (default-identification defsize) (make-identification-string 2.0 "" #false))

       (define peer-identification
         (lambda [idstring]
           (define-values (/dev/sshin /dev/sshout) (make-pipe #false '/dev/sshin '/dev/sshout))
           (write-message /dev/sshout idstring (string-length idstring))
           (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
             (read-client-identification /dev/sshin))))]
