#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-7.1

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "message.rkt")

(require "../../assignment.rkt")
(require "../configuration.rkt")
(require "../diagnostics.rkt")

(struct key
  ([secret : Bytes]
   [hash : Bytes]
   [traffic : Natural])
  #:transparent
  #:type-name Key)

(define ssh-kex/starts-with-peer : (-> Thread SSH-MSG-KEXINIT Input-Port SSH-Configuration (Values Thread))
  (lambda [parent peer-kexinit /dev/tcpin rfc]
    (thread
     (λ [] (let ([maybe-kexinit (thread-receive)])
             (when (ssh-message? maybe-kexinit)
               #;(ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
               #;(write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
               (void)))))))

(define ssh-kex/starts-with-self : (-> Thread Output-Port Index Thread)
  (lambda [parent /dev/sshout payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (let ([maybe-kexinit (thread-receive)])
               (when (ssh-message? maybe-kexinit)
                 #;(ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
                 #;(write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
                 (void))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex : (-> Thread Output-Port Index Thread)
  (lambda [parent /dev/sshout payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (let ([maybe-kexinit (thread-receive)])
               (when (ssh-message? maybe-kexinit)
                 #;(ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
                 #;(write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
                 (void))))))))
