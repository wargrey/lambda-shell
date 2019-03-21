#lang typed/racket/base

(provide (all-defined-out))

(require "packet.rkt")

(require "../../assignment.rkt")
(require "../assignment.rkt")
(require "../configuration.rkt")
(require "../diagnostics.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-message : (-> Output-Port SSH-Message SSH-Configuration Nonnegative-Fixnum)
  (lambda [/dev/tcpout msg rfc]
    (define traffic : Nonnegative-Fixnum (ssh-write-binary-packet /dev/tcpout (ssh-message->bytes msg) 0 ($ssh-payload-capacity rfc) 0))
    (ssh-log-message 'debug "sent ~a [~a]" (ssh-message-name msg) (~size traffic))
    traffic))

(define ssh-read-transport-message : (-> Input-Port SSH-Configuration (Values (U SSH-Message Bytes) Nonnegative-Fixnum))
  (lambda [/dev/tcpin rfc]
    (define-values (payload mac traffic) (ssh-read-binary-packet /dev/tcpin ($ssh-payload-capacity rfc) 0))
    (define message-id : Byte (bytes-ref payload 0))
    (define message-type : (U Symbol String) (or (ssh-message-number->name message-id) (format "unrecognized packet[~a]" message-id)))
    (ssh-log-message 'debug "received ~a [~a]" message-type (~size traffic))
    (values (or (ssh-bytes->message* payload ssh-msg-range/transport) payload)
            traffic)))

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

(define ssh-log-debug : (->* (SSH-MSG-DEBUG String) (Log-Level) Void)
  (lambda [msg prefix [level 'debug]]
    (when (ssh:msg:debug-display? msg)
      (ssh-log-message level "[DEBUG]~a says: ~a" (ssh:msg:debug-message msg)))))

(define ssh-log-disconnection : (->* (SSH-MSG-DISCONNECT String) (Log-Level) Void)
  (lambda [msg prefix [level 'debug]]
    (ssh-log-message level "~a disconnected with reason ~a(~a)"
                     (ssh:msg:disconnect-reason msg)
                     (ssh:msg:disconnect-description msg))))
