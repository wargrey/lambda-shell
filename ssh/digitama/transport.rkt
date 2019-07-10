#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/message.rkt")
(require "transport/kex.rkt")
(require "transport/newkeys.rkt")
(require "transport/prompt.rkt")

(require "message/transport.rkt")
(require "message/authentication.rkt")
(require "message/disconnection.rkt")

(require "diagnostics.rkt")

(require "../kex.rkt")
(require "../message.rkt")
(require "../configuration.rkt")

(struct ssh-transport
  ([custodian : Custodian]
   [preference : SSH-Configuration]
   [logger : Logger])
  #:type-name SSH-Transport)

(struct ssh-listener ssh-transport
  ([watchdog : TCP-Listener]
   [identification : String]
   [kexinit : SSH-MSG-KEXINIT]
   [local-name : Symbol]
   [port-number : Index])
  #:type-name SSH-Listener)

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
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-deliver-error e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT)
               (ssh-prompt #false
                           (λ [] (ssh-read-server-identification /dev/tcpin rfc))
                           (λ [[eof-msg : SSH-MSG-DISCONNECT]] eof-msg)))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification identification]
                            [current-server-identification (if (ssh-identification? peer) (ssh-identification-raw peer) identification)])
               (ssh-prompt (current-peer-name)
                           (λ [] (ssh-transport-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc #false))
                           /dev/sshout)))))))

(define sshd-ghostcat : (-> Output-Port String Input-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-deliver-error e /dev/sshout))])
             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT)
               (ssh-prompt #false
                           (λ [] (ssh-read-client-identification /dev/tcpin rfc))
                           (λ [[eof-msg : SSH-MSG-DISCONNECT]] eof-msg)))

             (ssh-write-text /dev/tcpout identification)
             (write-special peer /dev/sshout)

             (parameterize ([current-client-identification (if (ssh-identification? peer) (ssh-identification-raw peer) identification)]
                            [current-server-identification identification])
               (ssh-prompt (current-peer-name)
                           (λ [] (ssh-transport-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit rfc #true))
                           /dev/sshout)))))))

(define ssh-transport-loop : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (define rekex-traffic : Natural ($ssh-rekex-traffic rfc))
    (define self : Thread (current-thread))

    (let ghostcat-loop : Void ([rekex : (U SSH-Kex False) #false]
                               [rekexing : (Option SSH-Kex-Process) #false]
                               [kexinit : SSH-MSG-KEXINIT kexinit]
                               [newkeys : Maybe-Newkeys (make-ssh-parcel ($ssh-payload-capacity rfc))]
                               [sthgilfni : (Option (Listof SSH-Message)) #false] ; to reduce args, #false => |we haven't sent kexinit|
                               [incoming : Integer rekex-traffic]
                               [outgoing : Integer rekex-traffic]
                               [authenticated : Boolean #false])
      (define evt : Any
        (cond [(or (>= incoming rekex-traffic) (>= outgoing rekex-traffic)) kexinit]
              [else (sync/enable-break /dev/sshin /dev/tcpin)]))
      
      (cond [(tcp-port? evt)
             (define-values (msg payload traffic) (ssh-read-transport-message /dev/tcpin rfc newkeys (and rekex (ssh-kex-name rekex))))
             (define incoming++ : Integer (+ incoming traffic))
             (define ghostcat-step : (-> Void) (λ [] (ghostcat-loop rekex rekexing kexinit newkeys sthgilfni incoming++ outgoing authenticated)))
             
             (cond [(not msg) (ssh-deliver-message payload /dev/sshout authenticated) (ghostcat-step)]
                   [(ssh-ignored-incoming-message? msg) (ghostcat-step)]
                   [(and rekex #| coincide with |# rekexing)
                    (define maybe-newkeys : (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys) (rekexing rekex msg))
                    (if (pair? maybe-newkeys)
                        (let-values ([(kex-self reply) (values (car maybe-newkeys) (cdr maybe-newkeys))])
                          (ssh-write-message /dev/tcpout reply rfc newkeys)
                          (ghostcat-loop kex-self rekexing kexinit newkeys sthgilfni incoming++ outgoing authenticated))
                        (let ([session : Bytes (ssh-newkeys-identity maybe-newkeys)])
                          (ssh-write-message /dev/tcpout SSH:NEWKEYS rfc newkeys)
                          (write-special session /dev/sshout)
                          (let send-inflights ([inflights : (Listof SSH-Message) (if (list? sthgilfni) (reverse sthgilfni) null)]
                                               [flights-outgoing : Integer 0])
                            (cond [(null? inflights) (ghostcat-loop #false #false kexinit maybe-newkeys #false 0 flights-outgoing authenticated)]
                                  [else (send-inflights (cdr inflights) (+ flights-outgoing (ssh-write-message /dev/tcpout (car inflights) rfc maybe-newkeys)))]))))]
                   
                   [(ssh:msg:kexinit? msg)
                    (unless (list? sthgilfni) (ssh-write-message /dev/tcpout kexinit rfc newkeys))
                    (define maybe-kex-ing : (U (Pairof SSH-Kex SSH-Kex-Process) SSH-Message)
                      (cond [(and server?) (ssh-kex/server kexinit msg rfc newkeys payload)]
                            [else (let* ([maybe-kex.req (ssh-kex/client kexinit msg rfc newkeys payload)]
                                         [kex-self (car maybe-kex.req)])
                                    (and kex-self (ssh-write-message /dev/tcpout (cdr maybe-kex.req) rfc newkeys))
                                    (or kex-self (cdr maybe-kex.req)))]))
                    (cond [(ssh-message? maybe-kex-ing) #| kex failed |# (ssh-write-message /dev/tcpout maybe-kex-ing rfc newkeys) (ghostcat-step)]
                          [else (ghostcat-loop (car maybe-kex-ing) (cdr maybe-kex-ing) kexinit newkeys (or sthgilfni null) incoming++ outgoing authenticated)])]
                   
                   [(ssh:msg:service:request? msg)
                    (define service : Symbol (ssh:msg:service:request-name msg))
                    (define ssh-userauth? : Boolean (eq? service 'ssh-userauth))
                    (thread-send self
                                 (cond [(and (not authenticated) server? ssh-userauth?) (ssh-service-accept-message service)]
                                       [(and authenticated (not ssh-userauth?)) (write-special msg /dev/sshout)]
                                       [else (make-ssh:disconnect:service:not:available #:source ssh-transport-loop (ssh-service-reject-description service))]))
                    (ghostcat-step)]
                   
                   [else (write-special msg /dev/sshout) (ghostcat-step)])]
            
            [(ssh-message? evt)
             (if (not rekex)
                 (let ([traffic (ssh-write-message /dev/tcpout evt rfc newkeys)])
                   (if (ssh:msg:kexinit? evt)
                       (ghostcat-loop rekex rekexing evt newkeys null #|we have sent kexinit|# 0 0 authenticated)
                       (ghostcat-loop rekex rekexing kexinit newkeys sthgilfni incoming (+ outgoing traffic) (or authenticated (ssh:msg:userauth:success? evt)))))
                 (if (ssh-kex-transparent-message? evt)
                     (let ([traffic (ssh-write-message /dev/tcpout evt rfc newkeys)])
                       (ghostcat-loop rekex rekexing kexinit newkeys sthgilfni incoming (+ outgoing traffic) authenticated))
                     (ghostcat-loop rekex rekexing kexinit newkeys (if (list? sthgilfni) (cons evt sthgilfni) (list evt)) incoming outgoing authenticated)))]
            
            [(and (pair? evt) (ssh-newkeys? (car evt)) (exact-nonnegative-integer? (cdr evt)))
             (when (ssh-parcel? newkeys) ; the first key exchange, tell client the session identity
               (write-special (ssh-newkeys-identity (car evt)) /dev/sshout))
             (ghostcat-loop #false rekexing kexinit (car evt) sthgilfni 0 (cdr evt) authenticated)]
            
            [else ; maybe the application want to make jokes
             (define traffic : Integer (ssh-write-message /dev/tcpout (make-ssh:msg:ignore #:data (format "~s" evt)) rfc newkeys))
             (ghostcat-loop rekex rekexing kexinit newkeys sthgilfni incoming (+ outgoing traffic) authenticated)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-disconnect : (->* (Output-Port Symbol SSH-Configuration Maybe-Newkeys) ((U String exn False)) Natural)
  (lambda [/dev/tcpout reason rfc newkeys [details #false]]
    (define description : (Option String) (if (exn? details) (exn-message details) details))
    (define msg : SSH-Message (make-ssh:msg:disconnect #:reason reason #:description (or description (void))))
    
    (ssh-write-message /dev/tcpout msg rfc newkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-accept-message : (-> Symbol SSH-MSG-SERVICE-ACCEPT)
  (lambda [service]
    (make-ssh:msg:service:accept #:name service)))

(define ssh-service-reject-description : (-> Symbol String)
  (lambda [service]
    (format "service '~a' not available" service)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-pull-special : (All (a) (-> Input-Port (Option Nonnegative-Real) (-> Any Boolean : a) Procedure (U a SSH-MSG-DISCONNECT)))
  (lambda [/dev/sshin timeout ? func]
    (unless (cond [(not timeout) (sync/enable-break /dev/sshin)]
                  [else (sync/timeout/enable-break timeout /dev/sshin)])
      (ssh-raise-timeout-error func timeout))

    (define exn-or-datum (read-byte-or-special /dev/sshin))
    (cond [(exn? exn-or-datum) (raise exn-or-datum)]
          [(ssh:msg:disconnect? exn-or-datum) exn-or-datum]
          [else (assert exn-or-datum ?)])))

(define ssh-deliver-message : (-> Bytes Output-Port Boolean Void)
  (lambda [payload /dev/sshout authenticated]
    (define userauth? : Boolean (ssh-authentication-payload? payload))
    
    (when (if (not authenticated) userauth? (not userauth?))
      (write-special payload /dev/sshout)
      (void))))

(define ssh-deliver-error : (-> exn Output-Port Boolean)
  (lambda [e /dev/sshout]
    (write-special (make-ssh:disconnect:reserved #:source ssh-deliver-error "~a: ~a: ~a" (current-peer-name) (object-name e) (exn-message e))
                   /dev/sshout)))
