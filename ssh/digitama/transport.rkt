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
   [port-number : Index])
  #:type-name SSH-Listener)

(struct ssh-port ssh-transport
  ([ghostcat : Thread]
   [sshin : Input-Port])
  #:type-name SSH-Port)

(define sshc-ghostcat : (-> Output-Port String String Natural SSH-MSG-KEXINIT Symbol SSH-Configuration Thread)
  (lambda [/dev/sshout identification hostname port kexinit peer-name rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-server-identification /dev/tcpin rfc) /dev/sshout)

             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc #false))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT Symbol SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit peer-name rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (ssh-write-text /dev/tcpout identification)
             (write-special (ssh-read-client-identification /dev/tcpin rfc) /dev/sshout)
             
             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc #true))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT Symbol SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) #false]
                                           [kexinit : SSH-MSG-KEXINIT kexinit]
                                           [traffic : Natural 0])
      (define evt : Any
        (cond [(and (not maybe-rekex) (> traffic ($ssh-rekex-traffic rfc))) kexinit]
              [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task traffic++)
        (cond [(tcp-port? evt)
               (define-values (msg traffic) (ssh-read-transport-message /dev/tcpin rfc null))
               (define maybe-task : Any
                 (cond [(bytes? msg) (write-special msg /dev/sshout)]
                       [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout peer-name rfc server?)]
                       [(ssh:msg:disconnect? msg) (write-special eof /dev/sshout)]
                       [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
                       [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)]))
               (values (and (thread? maybe-task) maybe-task) traffic)]

              [(ssh-message? evt)
               (define-values (maybe-new-rekex traffic)
                 (if (not maybe-rekex)
                     (cond [(ssh:msg:kexinit? evt) (values (ssh-kex/starts-with-self evt /dev/tcpin /dev/tcpout peer-name rfc server?) 0)]
                           [else (values maybe-rekex (ssh-write-message /dev/tcpout evt rfc))])
                     (cond [(ssh-kex-transparent-message? evt) (values maybe-rekex (ssh-write-message /dev/tcpout evt rfc))]
                           [else (thread-send maybe-rekex evt) (values maybe-rekex 0)])))
               (values maybe-new-rekex traffic)]
              
              #;[(key? evtobj) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-rekex)]

              [(exn? evt)
               (cond [(exn:ssh:kex? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-KEY-EXCHANGE-FAILED rfc evt)]
                     [else (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-PROTOCOL-ERROR rfc evt)])
               (raise evt)]
              
              [else (values maybe-rekex 0)]))
      
      (sync-handle-feedback-loop maybe-task
                                 (if (ssh:msg:kexinit? evt) evt kexinit)
                                 (+ (if maybe-task 0 traffic)
                                    traffic++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-disconnect : (->* (Output-Port SSH-Disconnection-Reason SSH-Configuration) ((U String exn False)) Nonnegative-Fixnum)
  (lambda [/dev/tcpout reason rfc [details #false]]
    (define description : (Option String) (if (exn? details) (exn-message details) details))
    (ssh-write-message /dev/tcpout (make-ssh:msg:disconnect #:reason reason #:description description) rfc)))

(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))
