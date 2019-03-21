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
(require "configuration.rkt")
(require "diagnostics.rkt")

(struct ssh-transport
  ([root : Custodian] ; useless, just in order to satisfy the `custodian-managed-list`
   [custodian : Custodian]
   [preference : SSH-Configuration])
  #:type-name SSH-Transport)

(struct ssh-listener ssh-transport
  ([watchdog : TCP-Listener]
   [identification : String]
   [kexinit : SSH-MSG-KEXINIT]
   [name : String]
   [port : Index])
  #:type-name SSH-Listener)

(struct ssh-port ssh-transport
  ([ghostcat : Thread]
   [/dev/sshin : Input-Port]
   [peer-name : String])
  #:type-name SSH-Port)

(define sshc-ghostcat : (-> Output-Port String Natural SSH-Configuration Thread)
  (lambda [/dev/sshout hostname port rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
             (define-values (identification idsize) (ssh-identification-string rfc))
             (ssh-log-message 'debug "local identification string: ~a" (substring identification 0 idsize))
             (ssh-write-text /dev/tcpout identification idsize)
             (write-special (ssh-read-server-identification /dev/tcpin rfc) /dev/sshout)

             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout rfc))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin rfc) /dev/sshout)
             
             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout rfc))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-Configuration Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout rfc]
    ;(ssh-log-kexinit kexinit "local")
    ;(define server-key : SSH-MSG-KEXINIT (ssh-read-special /dev/pin ($ssh-timeout rfc) ssh:msg:kexinit? 'ssh-connect))
    ;(ssh-log-kexinit server-key "server")
    ;(displayln (ssh-read-special /dev/pin ($ssh-timeout rfc) ssh:msg:kexdh:init? 'ssh-connect))
    (define-values (/dev/keyin /dev/keyout) (make-pipe-with-specials))
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (let sync-handle-feedback-loop : Void ([maybe-task : (Option Thread) #false]
                                           [traffic : Natural 0])
      (define-values (rekex-task traffic-delta)
        (cond [(> traffic ($ssh-rekex-traffic rfc)) (values maybe-task 0)]
              [else (let ([evt (sync/enable-break /dev/sshin (if maybe-task /dev/keyin /dev/tcpin))])
                      (cond [(input-port? evt) (ssh-deal-with-incoming-message /dev/tcpin /dev/sshout rfc)]
                            [(ssh-message? evt) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-task)]
                            [(key? evt) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-task)]
                            [else (values maybe-task 0)]))]))
      (sync-handle-feedback-loop rekex-task (+ traffic traffic-delta)))))

(define ssh-deal-with-outgoing-message : (-> Output-Port SSH-Configuration (Option Thread) (Values (Option Thread) Nonnegative-Fixnum))
  (lambda [/dev/tcpout rfc maybe-task]
    (define msg/key (thread-receive))
    (cond [(key? msg/key) (void)]
          [else (values maybe-task 0)])
    (values maybe-task 0)))

(define ssh-deal-with-incoming-message : (-> Input-Port Output-Port SSH-Configuration (Values (Option Thread) Nonnegative-Fixnum))
  (lambda [/dev/tcpin /dev/sshout rfc]
    (define-values (msg traffic) (ssh-read-transport-message /dev/tcpin rfc))
    (define maybe-task : Any
      (cond [(bytes? msg) (write-special msg /dev/sshout)]
            [(ssh:msg:disconnect? msg) (ssh-log-disconnection msg "peer") (write-special eof /dev/sshout)]
            [(ssh:msg:ignore? msg) (void 'ignored)]
            [(ssh:msg:debug? msg) (ssh-log-debug msg "peer")]
            [(ssh:msg:unimplemented? msg) (void 'ignored)]
            [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer (current-thread) msg /dev/tcpin rfc)]
            [else (displayln msg)]))
    (values (and (thread? maybe-task) maybe-task) traffic)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))
