#lang scribble/lp2

@(require digimon/tamer)

@handbook-story{The Secure Shell Authentication Protocol}

This section demonstrates the implementation of @cite{SSH-USERAUTH}.

@;tamer-smart-summary[]

@handbook-scenario{Authentication Requests}

@tamer-repl[
 (ssh-message (make-ssh:msg:userauth:request #:username 'wargrey #:method 'none))
 (ssh-message (make-ssh:msg:userauth:request:publickey #:username 'wargrey #:algorithm 'algorithm #:key #"key"))
 (define-values (octets signed-request) (ssh-message (make-ssh:msg:userauth:request:publickey$ #:username 'wargrey #:signature #"signature" #:algorithm 'algorithm #:key #"key")))
 (values octets signed-request)
 (ssh:msg:userauth:request? signed-request)
 (ssh:msg:userauth:request:publickey? signed-request)]

@handbook-scenario{Authorized_keys}

The format of @deftech{authorized_keys} is defined in @exec{man sshd}.

@tamer-repl[
 (with-logging-to-port (current-error-port)
   (λ [] (read-authorized-keys* authorized_keys #:count-lines? #true))
   'debug)]

@handbook-reference[#:auto-hide? #false]

@; Chunks after `handbook-reference[#:auto-hide? #false]` will never be rendered in document

@chunk[|<authentication:*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <request>)]

@chunk[<request>
       (require racket/logging)

       (require "message.rkt")
       
       (require "../digitama/message/authentication.rkt")
       (require "../digitama/authentication/publickey.rkt")
       (require "../digitama/fsio/authorized-keys.rkt")

       (define authorized_keys (digimon-path "tamer" "stone" "authorized_keys"))]
