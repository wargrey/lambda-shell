#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/packet.rkt")

(require "../assignment.rkt")
(require "diagnostics.rkt")

(struct SSH-Listener
  ([custodian : Custodian]
   [watchdog : TCP-Listener]
   [identification : String]))

(struct SSH-Port
  ([custodian : Custodian]
   [ghostcat : Thread]
   [/dev/sshin : Input-Port]))

(define sshc-ghostcat : (-> Output-Port String Natural Positive-Flonum (Option String) (Option String) Index Thread)
  (lambda [/dev/sshout hostname port protoversion softwareversion comments payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define-values (identification idsize) (ssh-identification-string protoversion (or softwareversion "") comments))
             (ssh-write-text /dev/tcpout identification idsize)
             (write-special (ssh-read-server-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
                 (write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout))))))))

(define sshd-ghostcat : (-> String Input-Port Output-Port Index Output-Port Thread)
  (lambda [identification /dev/tcpin /dev/tcpout payload-capacity /dev/sshout]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
                 (ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-read-transport-message : (-> Input-Port Index Index (U SSH-Message Bytes))
  (lambda [/dev/sshin payload-capacity mac-length]
    (define-values (payload mac) (ssh-read-binary-packet /dev/sshin payload-capacity 0))
    (or (ssh-bytes->message* payload ssh-msg-range/transport)
        payload)))
