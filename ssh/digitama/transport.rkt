#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/packet.rkt")

(require "../assignment.rkt")
(require "assignment.rkt")
(require "diagnostics.rkt")

(struct SSH-Listener
  ([custodian : Custodian]
   [watchdog : TCP-Listener]
   [identification : String]
   [kexinit : SSH-MSG-KEXINIT]
   [name : String]
   [port : Index]))

(struct SSH-Port
  ([custodian : Custodian]
   [ghostcat : Thread]
   [/dev/sshin : Input-Port]
   [peer-name : String]))

(define sshc-ghostcat : (-> Output-Port String Natural Positive-Flonum (Option String) (Option String) Index Thread)
  (lambda [/dev/sshout hostname port protoversion softwareversion comments payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
             (define-values (identification idsize) (ssh-identification-string protoversion (or softwareversion "") comments))
             (ssh-log-message 'debug "local identification string: ~a" (substring identification 0 idsize))
             (ssh-write-text /dev/tcpout identification idsize)
             (write-special (ssh-read-server-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (ssh-write-binary-packet /dev/tcpout (ssh-message->bytes maybe-kexinit) 0 payload-capacity 0)
                 (write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout))))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port Index Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout payload-capacity]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin) /dev/sshout)

             (let ([maybe-kexinit (thread-receive)])
               (when (SSH-Message? maybe-kexinit)
                 (write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout)
                 (ssh-write-message /dev/tcpout maybe-kexinit 0 payload-capacity 0)
                 (write-special (ssh-read-transport-message /dev/tcpin payload-capacity 0) /dev/sshout))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-message : (-> Output-Port SSH-Message Byte Index Byte Void)
  (lambda [/dev/sshout msg cipher-blocksize payload-capacity mac-length]
    (define sent : Nonnegative-Fixnum
      (ssh-write-binary-packet /dev/sshout (ssh-message->bytes msg) cipher-blocksize payload-capacity mac-length))
    (ssh-log-message 'debug "sent ~a [~a]" (ssh-message-name msg) (~size sent))))

(define ssh-read-transport-message : (-> Input-Port Index Index (U SSH-Message Bytes))
  (lambda [/dev/sshin payload-capacity mac-length]
    (define-values (payload mac received) (ssh-read-binary-packet /dev/sshin payload-capacity 0))
    (ssh-log-message 'debug "received ~a [~a]" (ssh-message-number->name (bytes-ref payload 0)) (~size received))
    (or (ssh-bytes->message* payload ssh-msg-range/transport)
        payload)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-kexinit : (->* (SSH-MSG-KEXINIT String) (Log-Level) Void)
  (lambda [msg prefix [level 'debug]]
    (ssh-log-message level "~a KEX algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-kex-methods msg)))
    (ssh-log-message level "~a host key algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-key-formats msg)))
    (ssh-log-message level "~a c2s encryption algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-c2s-ciphers msg)))
    (ssh-log-message level "~a s2c encryption algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-s2c-ciphers msg)))
    (ssh-log-message level "~a c2s MAC algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-c2s-mac-algorithms msg)))
    (ssh-log-message level "~a s2c MAC algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-s2c-mac-algorithms msg)))
    (ssh-log-message level "~a c2s compression algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-c2s-compression-methods msg)))
    (ssh-log-message level "~a s2c compression algorithms: ~a" prefix (ssh-algorithms->names (ssh:msg:kexinit-s2c-compression-methods msg)))))
