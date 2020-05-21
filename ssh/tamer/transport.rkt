#lang scribble/lp2

@(require digimon/tamer)

@handbook-story{The Secure Shell Transport Layer Protocol}

This section demonstrates the implementation of @cite{SSH-TRANS}.

@tamer-smart-summary[]

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
 (ssh-message (make-ssh:msg:ignore #:data #"Ignored Data Message"))
 (ssh-message (make-ssh:msg:debug #:display? #true #:message "调试信息 in ISO-10646 UTF-8 encoding [RFC3629]" #:language 'zh_CN))
 (ssh-message (make-ssh:msg:unimplemented #:number 0))
 (ssh-message (make-ssh:msg:newkeys))]

@handbook-reference[#:auto-hide? #false]

@; Chunks after `handbook-reference[#:auto-hide? #false]` will never be rendered in documents

@chunk[|<transport:*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module tamer typed/racket
         (require "message.rkt")
       
         (require "../transport.rkt") ; import builtin algorithms
         (require "../configuration.rkt")
         
         (require "../digitama/message/transport.rkt")
         (require "../digitama/transport/identification.rkt")
         (require "../digitama/transport/prompt.rkt")
         
         <identification>)]

@chunk[<identification>
       (define rfc : SSH-Configuration (make-ssh-configuration))
       (define default-identification : String (ssh-identification-string rfc))

       (define ssh-peer-identification : (-> String (U SSH-Identification Void))
         (lambda [idstring]
           (define-values (/dev/sshin /dev/sshout) (make-pipe))
           (ssh-write-text /dev/sshout idstring (string-length idstring))

           (ssh-prompt #false
                       (λ [] (ssh-read-client-identification /dev/sshin rfc))
                       (λ [[eof-msg : SSH-MSG-DISCONNECT]]
                         (fprintf (current-error-port) "~a~n  ~a~n"
                                  (ssh:msg:disconnect-reason eof-msg)
                                  (ssh:msg:disconnect-description eof-msg))))))]
