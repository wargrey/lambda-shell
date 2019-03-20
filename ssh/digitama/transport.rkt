#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/packet.rkt")
(require "transport/message.rkt")
(require "transport/kex.rkt")

(require "../assignment.rkt")
(require "assignment.rkt")
(require "option.rkt")
(require "diagnostics.rkt")

(struct SSH-Listener
  ([custodian : Custodian]
   [watchdog : TCP-Listener]
   [identification : String]
   [kexinit : SSH-MSG-KEXINIT]
   [option : SSH-Option]
   [name : String]
   [port : Index]))

(struct SSH-Port
  ([custodian : Custodian]
   [ghostcat : Thread]
   [/dev/sshin : Input-Port]
   [peer-name : String]))

(define sshc-ghostcat : (-> Output-Port String Natural SSH-Option Thread)
  (lambda [/dev/sshout hostname port option]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
             (define-values (identification idsize) (ssh-identification-string option))
             (ssh-log-message 'debug "local identification string: ~a" (substring identification 0 idsize))
             (ssh-write-text /dev/tcpout identification idsize)
             (write-special (ssh-read-server-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 (ssh-option-payload-capacity option) 0)
                 (write-special (ssh-read-transport-message /dev/tcpin (ssh-option-payload-capacity option) 0) /dev/sshout))))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-Option Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout option]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (write-special (ssh-read-transport-message /dev/tcpin (ssh-option-payload-capacity option) 0) /dev/sshout)
                 (ssh-write-message /dev/tcpout maybe-kexinit 0 (ssh-option-payload-capacity option) 0)
                 (write-special (ssh-read-transport-message /dev/tcpin (ssh-option-payload-capacity option) 0) /dev/sshout))))))))
