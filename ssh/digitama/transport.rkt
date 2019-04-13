#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/packet.rkt")
(require "transport/message.rkt")
(require "transport/kex.rkt")
(require "transport/newkeys.rkt")

(require "diagnostics.rkt")

(require "../message.rkt")
(require "../assignment.rkt")
(require "../configuration.rkt")

(struct ssh-transport
  ([root : Custodian] ; useless, just in order to satisfy the `custodian-managed-list`
   [custodian : Custodian]
   [preference : SSH-Configuration]
   [logger : Logger])
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

(define sshc-ghostcat : (-> Output-Port String String Natural SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification hostname port kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special (if (exn:ssh:eof? e) eof e) /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define peer : SSH-Identification (ssh-read-server-identification /dev/tcpin rfc))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification identification]
                            [current-server-identification (ssh-identification-raw peer)])
               (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc #false)))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special (if (exn:ssh:eof? e) eof e) /dev/sshout))])
             (define peer : SSH-Identification (ssh-read-client-identification /dev/tcpin rfc))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification (ssh-identification-raw peer)]
                            [current-server-identification identification])
               (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc  #true)))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) #false]
                                           [kexinit : SSH-MSG-KEXINIT kexinit]
                                           [newkeys : (Option SSH-Kex-Newkeys) #false]
                                           [traffic : Natural 0])
      (define evt : Any
        (cond [(and (not maybe-rekex) (> traffic ($ssh-rekex-traffic rfc))) kexinit]
              [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task traffic++)
        (cond [(tcp-port? evt)
               (define-values (msg payload traffic) (ssh-read-transport-message /dev/tcpin rfc newkeys null))
               (define maybe-task : Any
                 (cond [(not msg) (write-special payload /dev/sshout)]
                       [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout rfc newkeys payload server?)]
                       [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
                       [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)]))
               (values (and (thread? maybe-task) maybe-task) traffic)]

              [(ssh-message? evt)
               (if (not maybe-rekex)
                   (cond [(ssh:msg:kexinit? evt) (values (ssh-kex/starts-with-self evt /dev/tcpin /dev/tcpout rfc newkeys server?) 0)]
                         [else (values maybe-rekex (ssh-write-message /dev/tcpout evt rfc newkeys))])
                   (cond [(ssh-kex-transparent-message? evt) (values maybe-rekex (ssh-write-message /dev/tcpout evt rfc newkeys))]
                         [else (thread-send maybe-rekex evt) (values maybe-rekex 0)]))]
              
              #;[(ssh-kex-newkeys? evtobj) (ssh-deal-with-outgoing-message /dev/tcpout rfc maybe-rekex)]

              [(exn? evt)
               (cond [(exn:ssh:kex? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-KEY-EXCHANGE-FAILED rfc newkeys evt)]
                     [(not (exn:ssh:eof? evt)) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-PROTOCOL-ERROR rfc newkeys evt)])
               (raise evt)]
              
              [else (values maybe-rekex 0)]))
      
      (sync-handle-feedback-loop maybe-task
                                 (if (ssh:msg:kexinit? evt) evt kexinit)
                                 newkeys
                                 (+ (if maybe-task 0 traffic)
                                    traffic++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-disconnect : (->* (Output-Port SSH-Disconnection-Reason SSH-Configuration (Option SSH-Kex-Newkeys)) ((U String exn False)) Nonnegative-Fixnum)
  (lambda [/dev/tcpout reason rfc newkeys [details #false]]
    (define description : (Option String) (if (exn? details) (exn-message details) details))
    (define msg : SSH-Message (make-ssh:msg:disconnect #:reason reason #:description description))
    (ssh-write-message /dev/tcpout msg rfc newkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))

(define ssh-read-special : (All (a) (-> Input-Port (Option Nonnegative-Real) (-> Any Boolean : a) Procedure a))
  (lambda [/dev/sshin timeout ? func]
    (unless (cond [(not timeout) (sync/enable-break /dev/sshin)]
                  [else (sync/timeout/enable-break timeout /dev/sshin)])
      (ssh-raise-timeout-error func timeout))

    (define exn-or-datum (read-byte-or-special /dev/sshin))
    (cond [(exn? exn-or-datum) (raise exn-or-datum)]
          [else (assert exn-or-datum ?)])))
