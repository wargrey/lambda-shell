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

(define sshc-ghostcat : (-> Output-Port String String Natural SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification hostname port kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-server-identification /dev/tcpin rfc) /dev/sshout)

             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc #false))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin rfc) /dev/sshout)
             
             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc #true))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) (ssh-kex/starts-with-self kexinit /dev/tcpin /dev/tcpout rfc server?)]
                                           [kexinit : SSH-MSG-KEXINIT kexinit]
                                           [traffic : Natural 0])
      (define evt : Any
        (cond [(and (not maybe-rekex) (> traffic ($ssh-rekex-traffic rfc))) kexinit]
              [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task traffic++)
        (cond [(tcp-port? evt) (ssh-deal-with-incoming-message /dev/tcpin /dev/sshout kexinit rfc /dev/tcpout server?)]
              [(ssh-message? evt) (ssh-deal-with-outgoing-message evt /dev/tcpout rfc /dev/tcpin maybe-rekex server?)]
              #;[(key? evtobj) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-rekex)]
              [(thread? evt) (throw exn:ssh:eof /dev/tcpin 'rekex "unexpected termination of rekex thread")] 
              [else (values maybe-rekex 0)]))
      
      (sync-handle-feedback-loop maybe-task
                                 (if (ssh:msg:kexinit? evt) evt kexinit)
                                 (+ (if maybe-task 0 traffic)
                                    traffic++)))))

(define ssh-deal-with-outgoing-message : (-> SSH-Message Output-Port SSH-Configuration Input-Port (Option Thread) Boolean (Values (Option Thread) Nonnegative-Fixnum))
  (lambda [msg /dev/tcpout rfc /dev/tcpin maybe-rekex server?]
    (define-values (maybe-new-rekex traffic)
      (if (not maybe-rekex)
          (cond [(ssh:msg:kexinit? msg) (values (ssh-kex/starts-with-self msg /dev/tcpin /dev/tcpout rfc server?) 0)]
                [else (values maybe-rekex (ssh-write-message /dev/tcpout msg rfc))])
          (cond [(ssh-kex-transparent-message? msg) (values maybe-rekex (ssh-write-message /dev/tcpout msg rfc))]
                [else (thread-send maybe-rekex msg) (values maybe-rekex 0)])))
    (values maybe-new-rekex traffic)))

(define ssh-deal-with-incoming-message : (-> Input-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Output-Port Boolean (Values (Option Thread) Nonnegative-Fixnum))
  (lambda [/dev/tcpin /dev/sshout kexinit rfc /dev/tcpout server?]
    (define-values (msg traffic) (ssh-read-transport-message /dev/tcpin rfc null))
    (define maybe-task : Any
      (cond [(bytes? msg) (write-special msg /dev/sshout)]
            [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout rfc server?)]
            [(ssh:msg:disconnect? msg) (write-special eof /dev/sshout)]
            [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
            [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)]))
    (values (and (thread? maybe-task) maybe-task) traffic)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))
