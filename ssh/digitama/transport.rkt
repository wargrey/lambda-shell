#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/packet.rkt")
(require "transport/message.rkt")
(require "transport/kex.rkt")

(require "diagnostics.rkt")

(require "../message.rkt")
(require "../assignment.rkt")
(require "../configuration.rkt")

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
             (define peer : SSH-Identification (ssh-read-server-identification /dev/tcpin rfc peer-name))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc
                                            identification (ssh-identification-raw peer) #false))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT Symbol SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit peer-name rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/sshout))])
             (define peer : SSH-Identification (ssh-read-client-identification /dev/tcpin rfc))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)
             
             (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc
                                            (ssh-identification-raw peer) identification #true))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT Symbol SSH-Configuration String String Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit peer-name rfc Vc Vs server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) #false]
                                           [kexinit : SSH-MSG-KEXINIT kexinit]
                                           [traffic : Natural 0])
      (define evt : Any
        (cond [(and (not maybe-rekex) (> traffic ($ssh-rekex-traffic rfc))) kexinit]
              [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task traffic++)
        (cond [(tcp-port? evt)
               (define-values (msg traffic) (ssh-read-transport-message /dev/tcpin peer-name rfc null))
               (define maybe-task : Any
                 (cond [(bytes? msg) (write-special msg /dev/sshout)]
                       [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs server?)]
                       [(ssh:msg:disconnect? msg) (write-special eof /dev/sshout)]
                       [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
                       [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)]))
               (values (and (thread? maybe-task) maybe-task) traffic)]

              [(ssh-message? evt)
               (define-values (maybe-new-rekex traffic)
                 (if (not maybe-rekex)
                     (cond [(ssh:msg:kexinit? evt) (values (ssh-kex/starts-with-self evt /dev/tcpin /dev/tcpout peer-name rfc Vc Vs server?) 0)]
                           [else (values maybe-rekex (ssh-write-message /dev/tcpout evt peer-name rfc))])
                     (cond [(ssh-kex-transparent-message? evt) (values maybe-rekex (ssh-write-message /dev/tcpout evt peer-name rfc))]
                           [else (thread-send maybe-rekex evt) (values maybe-rekex 0)])))
               (values maybe-new-rekex traffic)]
              
              #;[(key? evtobj) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-rekex)]

              [(exn? evt)
               (cond [(exn:ssh:kex? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-KEY-EXCHANGE-FAILED peer-name rfc evt)]
                     [(not (exn:ssh:eof? evt)) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-PROTOCOL-ERROR peer-name rfc evt)])
               (raise evt)]
              
              [else (values maybe-rekex 0)]))
      
      (sync-handle-feedback-loop maybe-task
                                 (if (ssh:msg:kexinit? evt) evt kexinit)
                                 (+ (if maybe-task 0 traffic)
                                    traffic++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-disconnect : (->* (Output-Port SSH-Disconnection-Reason Symbol SSH-Configuration) ((U String exn False)) Nonnegative-Fixnum)
  (lambda [/dev/tcpout reason peer-name rfc [details #false]]
    (define description : (Option String) (if (exn? details) (exn-message details) details))
    (ssh-write-message /dev/tcpout (make-ssh:msg:disconnect #:reason reason #:description description) peer-name rfc)))

(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))

(define ssh-read-special : (All (a) (-> Input-Port (Option Nonnegative-Real) (-> Any Boolean : a) Procedure Symbol a))
  (lambda [/dev/sshin timeout ? func peer-name]
    (unless (cond [(not timeout) (sync/enable-break /dev/sshin)]
                  [else (sync/timeout/enable-break timeout /dev/sshin)])
      (ssh-raise-timeout-error func peer-name timeout))

    (define exn-or-datum (read-byte-or-special /dev/sshin))
    (cond [(exn? exn-or-datum) (raise exn-or-datum)]
          [else (assert exn-or-datum ?)])))
