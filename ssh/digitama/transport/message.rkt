#lang typed/racket/base

(provide (all-defined-out))

(require "packet.rkt")

(require "../../assignment.rkt")
(require "../assignment.rkt")
(require "../diagnostics.rkt")

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
