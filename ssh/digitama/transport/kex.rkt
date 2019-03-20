#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "message.rkt")

(require "../assignment.rkt")
(require "../diagnostics.rkt")

(define ssh-kex : (-> Thread Output-Port Index Thread)
  (lambda [parent /dev/sshout payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 #;(ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
                 #;(write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
                 (void))))))))
