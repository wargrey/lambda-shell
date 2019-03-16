#lang scribble/lp2

@(require digimon/tamer)

@(define-bib SSH-TRANS
   #:title    "The Secure Shell Transport Layer Protocol"
   #:author   (org-author-name "RFC4253")
   #:date     2006
   #:url      "https://tools.ietf.org/html/rfc4253")

@handbook-story{The Secure Shell Transport Layer Protocol}

This section demonstrates the implementation of @~cite[SSH-TRANS].

@;tamer-smart-summary[]

@handbook-scenario{Identification String}

@tamer-action[
 default-identification
 (ssh-peer-identification default-identification)]

@tamer-action[
 (ssh-peer-identification "SSL-2.0-Bad_Prefix")
 (ssh-peer-identification "SSH-1.b-Bad_Protocol")
 (ssh-peer-identification "SSH-2.0--")
 (ssh-peer-identification (~a "SSH-2.0-tl_dr " (make-string SSH-LONGEST-IDENTIFICATION-LENGTH #\.)))]

@handbook-scenario{Additional Messages}

@tamer-action[
 (ssh-message (make-ssh:msg:disconnect #:reason 'SSH_DISCONNECT_RESERVED #:language 'en_US))
 (ssh-message (make-ssh:msg:ignore #:data "Ignored Data Message"))
 (ssh-message (make-ssh:msg:debug #:display? #true #:message "调试信息 in ISO-10646 UTF-8 encoding [RFC3629]" #:language 'zh_CN))
 (ssh-message (make-ssh:msg:unimplemented #:number 0))
 #;(bytes->ssh:msg:kexinit (ssh:msg:kexinit->bytes (make-ssh:msg:kexinit #:cookie (make-bytes 16))))]


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
       (require "../assignment.rkt")

       (define-values (default-identification defsize) (make-identification-string 2.0 "" #false))

       (define ssh-peer-identification
         (lambda [idstring]
           (define-values (/dev/sshin /dev/sshout) (make-pipe #false '/dev/sshin '/dev/sshout))
           (write-message /dev/sshout idstring (string-length idstring))
           (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
             (read-client-identification /dev/sshin))))

       (define ssh-message
         (lambda [self]
           (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
             (define payload (ssh-message->bytes self))
             (values payload (ssh-bytes->message payload)))))]
