#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
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

(struct ssh-daemon ssh-transport
  ([watchdog : TCP-Listener]
   [identification : String]
   [kexinit : SSH-MSG-KEXINIT]
   [services : (Listof Symbol)]
   [local-name : Symbol]
   [port-number : Index])
  #:type-name SSH-Daemon)

(struct ssh-port ssh-transport
  ([peer-name : Symbol]
   [identity : Bytes]
   [ghostcat : Thread]
   [sshin : Input-Port])
  #:type-name SSH-Port)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define sshc-ghostcat : (-> Output-Port String String Natural SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification hostname port kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-write-special-error e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define peer : SSH-Identification (ssh-read-server-identification /dev/tcpin rfc))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification identification]
                            [current-server-identification (ssh-identification-raw peer)])
               (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit null rfc #false)))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT (Listof Symbol) SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit service rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-write-special-error e /dev/sshout))])
             (define peer : SSH-Identification (ssh-read-client-identification /dev/tcpin rfc))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification (ssh-identification-raw peer)]
                            [current-server-identification identification])
               (ssh-sync-handle-feedback-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit service rfc #true)))))))

(define ssh-sync-handle-feedback-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT (Listof Symbol) SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit services rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (define rekex-traffic : Natural ($ssh-rekex-traffic rfc))
    (define self : Thread (current-thread))
    
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) #false]
                                           [kexinit : SSH-MSG-KEXINIT kexinit]
                                           [newkeys : Maybe-Newkeys (make-ssh-parcel ($ssh-payload-capacity rfc))]
                                           [incoming-traffic : Integer rekex-traffic]
                                           [outgoing-traffic : Integer rekex-traffic])
      (define evt : Any
        (cond [(and (not maybe-rekex) (or (>= incoming-traffic rekex-traffic) (>= outgoing-traffic rekex-traffic))) kexinit]
              [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task maybe-newkeys incoming++ outgoing++)
        (cond [(tcp-port? evt)
               (define-values (msg payload itraffic++) (ssh-read-transport-message /dev/tcpin rfc newkeys null))
               (define maybe-task : Any
                 (cond [(not msg) (write-special payload /dev/sshout)]
                       [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout rfc newkeys payload server?)]
                       [(ssh-message-undefined? msg) (thread-send self (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
                       [(ssh-ignored-incoming-message? msg) (void)]
                       [(not (ssh:msg:service:request? msg)) (write-special msg /dev/sshout)]
                       [else (let ([service (ssh:msg:service:request-name msg)])
                               (thread-send self (cond [(memq service services) (ssh-service-accept-message service)]
                                                       [else (make-ssh:msg:disconnect #:reason 'SSH-DISCONNECT-SERVICE-NOT-AVAILABLE
                                                                                      #:description (ssh-service-reject-description service))])))]))
               (values (and (thread? maybe-task) maybe-task) newkeys itraffic++ 0)]

              [(ssh-message? evt)
               (if (not maybe-rekex)
                   (cond [(ssh:msg:kexinit? evt) (values (ssh-kex/starts-with-self evt /dev/tcpin /dev/tcpout rfc newkeys server?) newkeys 0 0)]
                         [else (values maybe-rekex newkeys 0 (ssh-write-message /dev/tcpout evt rfc newkeys))])
                   (cond [(ssh-kex-transparent-message? evt) (values maybe-rekex newkeys 0 (ssh-write-message /dev/tcpout evt rfc newkeys))]
                         [else (thread-send maybe-rekex evt) (values maybe-rekex newkeys 0 0)]))]
              
              [(and (pair? evt) (ssh-newkeys? (car evt)) (exact-nonnegative-integer? (cdr evt)))
               (when (ssh-parcel? newkeys) ; the first key exchange, tell client the session identity
                 (write-special (ssh-newkeys-identity (car evt)) /dev/sshout))
               (values #false (car evt) (- incoming-traffic) (- (cdr evt) outgoing-traffic))]

              [(exn? evt)
               (cond [(exn:ssh:kex:hostkey? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-HOST-KEY-NOT-VERIFIABLE rfc newkeys evt)]
                     [(exn:ssh:kex? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-KEY-EXCHANGE-FAILED rfc newkeys evt)]
                     [(exn:ssh:mac? evt) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-MAC-ERROR rfc newkeys evt)]
                     [(not (exn:ssh:eof? evt)) (ssh-disconnect /dev/tcpout 'SSH-DISCONNECT-PROTOCOL-ERROR rfc newkeys evt)])
               (raise evt)]
        
              [else (values maybe-rekex newkeys 0 0)]))
      
      (sync-handle-feedback-loop maybe-task (if (ssh:msg:kexinit? evt) evt kexinit) maybe-newkeys
                                 (+ incoming-traffic incoming++) (+ outgoing-traffic outgoing++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-disconnect : (->* (Output-Port SSH-Disconnection-Reason SSH-Configuration Maybe-Newkeys) ((U String exn False)) Natural)
  (lambda [/dev/tcpout reason rfc newkeys [details #false]]
    (define description : (Option String) (if (exn? details) (exn-message details) details))
    (define msg : SSH-Message (make-ssh:msg:disconnect #:reason reason #:description description))
    
    (ssh-write-message /dev/tcpout msg rfc newkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-accept-message : (-> Symbol SSH-MSG-SERVICE-ACCEPT)
  (lambda [service]
    (make-ssh:msg:service:accept #:name service)))

(define ssh-service-reject-description : (-> Symbol String)
  (lambda [service]
    (format "service '~a' not available" service)))

(define ssh-sync-disconnect : (->* (Thread SSH-Disconnection-Reason) ((Option String)) Void)
  (lambda [self reason [description #false]]
    (thread-send self (make-ssh:msg:disconnect #:reason reason #:description description))
    (thread-wait self)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-read-special : (All (a) (-> Input-Port (Option Nonnegative-Real) (-> Any Boolean : a) Procedure a))
  (lambda [/dev/sshin timeout ? func]
    (unless (cond [(not timeout) (sync/enable-break /dev/sshin)]
                  [else (sync/timeout/enable-break timeout /dev/sshin)])
      (ssh-raise-timeout-error func timeout))

    (define exn-or-datum (read-byte-or-special /dev/sshin))
    (cond [(exn? exn-or-datum) (raise exn-or-datum)]
          [else (assert exn-or-datum ?)])))

(define ssh-write-special-error : (-> exn Output-Port Boolean)
  (lambda [e /dev/sshout]
    (cond [(not (exn:ssh:eof? e)) (write-special e /dev/sshout)]
          [else (let ([reason (assert (exn:ssh:eof-reason e) SSH-Disconnection-Reason?)])
                  (write-special (make-ssh:msg:disconnect #:reason reason #:description (exn-message e))
                                 /dev/sshout))])))
