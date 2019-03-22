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
    (ssh-log-sent-message msg traffic 'debug)
    traffic))

(define ssh-read-transport-message : (-> Input-Port SSH-Configuration (Values (U SSH-Message Bytes) Nonnegative-Fixnum))
  (lambda [/dev/tcpin rfc]
    (define-values (payload mac traffic) (ssh-read-binary-packet /dev/tcpin ($ssh-payload-capacity rfc) 0))
    (define message-id : Byte (bytes-ref payload 0))
    (define message-type : (U Symbol String) (or (ssh-message-number->name message-id) (format "unrecognized message[~a]" message-id)))
    (define maybe-trans-msg : (Option SSH-Message) (ssh-bytes->transport-message payload))
    (ssh-log-message 'debug "received ~a [~a]" message-type (~size traffic))
    (unless (not maybe-trans-msg)
      (ssh-log-received-message maybe-trans-msg traffic 'debug)
      (when (ssh:msg:debug? maybe-trans-msg)
        (($ssh-debug-message-handler rfc)
         (ssh:msg:debug-display? maybe-trans-msg) (ssh:msg:debug-message maybe-trans-msg) (ssh:msg:debug-language maybe-trans-msg))))
    (values (or maybe-trans-msg payload) traffic)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex-transparent-message? : (-> SSH-Message Boolean)
  (lambda [msg]
    (and (ssh-transport-message? msg)
         (not (or (ssh:msg:service:request? msg)
                  (ssh:msg:service:accept? msg)
                  (ssh:msg:kexinit? msg))))))

(define ssh-ignored-incoming-message? : (-> SSH-Message Boolean)
  (lambda [msg]
    (or (ssh:msg:ignore? msg)
        (ssh:msg:debug? msg)
        (ssh:msg:unimplemented? msg))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-kexinit : (->* (SSH-MSG-KEXINIT String) (Log-Level) Void)
  (lambda [msg prefix [level 'debug]]
    (ssh-log-message level "~a KEX algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-kexes msg)))
    (ssh-log-message level "~a host key algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-hostkeys msg)))
    (ssh-log-message level "~a c2s encryption algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-ciphers msg)))
    (ssh-log-message level "~a s2c encryption algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-ciphers msg)))
    (ssh-log-message level "~a c2s MAC algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-macs msg)))
    (ssh-log-message level "~a s2c MAC algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-macs msg)))
    (ssh-log-message level "~a c2s compression algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-c2s-compressions msg)))
    (ssh-log-message level "~a s2c compression algorithms: ~a" prefix (map (inst car Symbol Any) (ssh:msg:kexinit-s2c-compressions msg)))))

(define ssh-log-sent-message : (->* (SSH-Message Nonnegative-Fixnum) (Log-Level) Void)
  (lambda [msg traffic [level 'debug]]
    (cond [(ssh:msg:disconnect? msg)
           (ssh-log-message level "terminate the connection because of ~a(~a)"
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          #;[])))

(define ssh-log-received-message : (->* (SSH-Message Nonnegative-Fixnum) (Log-Level) Void)
  (lambda [msg traffic [level 'debug]]
    (cond [(ssh:msg:debug? msg)
           (when (ssh:msg:debug-display? msg)
             (ssh-log-message level "[DEBUG]~a says: ~a" (ssh:msg:debug-message msg)))]
          [(ssh:msg:disconnect? msg)
           (ssh-log-message level "peer has disconnected with the reason ~a(~a)"
                            (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg))]
          [(ssh:msg:unimplemented? msg)
           (let ([id (ssh:msg:unimplemented-number msg)])
             (ssh-log-message level "peer cannot deal with message ~a"
                              (cond [(and (byte? id) (ssh-message-number->name id)) => values]
                                    [else id])))])))
