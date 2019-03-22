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
 (ssh-peer-identification default-identification)
 (ssh-peer-identification "SSH-2.0--")]

@tamer-action[
 (ssh-peer-identification "SSL-2.0-Bad_Prefix")
 (ssh-peer-identification "SSH-1.b-Bad_Protocol")
 (ssh-peer-identification (~a "SSH-2.0-tl_dr " (make-string ($ssh-longest-identification-length rfc) #\.)))]

@handbook-scenario{Additional Messages}

@tamer-action[
 (ssh-message (make-ssh:msg:kexinit))]

@tamer-action[
 (ssh-message (make-ssh:msg:disconnect #:reason 'SSH_DISCONNECT_RESERVED #:language 'en_US))
 (ssh-message (make-ssh:msg:ignore #:data "Ignored Data Message"))
 (ssh-message (make-ssh:msg:debug #:display? #true #:message "调试信息 in ISO-10646 UTF-8 encoding [RFC3629]" #:language 'zh_CN))
 (ssh-message (make-ssh:msg:unimplemented #:number 0))
 (ssh-message (make-ssh:msg:newkeys))]


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
       (require "../digitama/configuration.rkt")
       (require "../assignment.rkt")

       (define rfc (make-ssh-configuration))
       (define default-identification (ssh-identification-string rfc))

       (define ssh-peer-identification
         (lambda [idstring]
           (define-values (/dev/sshin /dev/sshout) (make-pipe #false '/dev/sshin '/dev/sshout))
           (ssh-write-text /dev/sshout idstring (string-length idstring))
           (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
             (ssh-read-client-identification /dev/sshin rfc))))

       (define ssh-message
         (lambda [self]
           (with-handlers ([exn:fail? (λ [e] (displayln (exn-message e) (current-error-port)))])
             (define payload (ssh-message->bytes self))
             (values payload (ssh-bytes->message payload)))))]
