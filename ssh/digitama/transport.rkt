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
             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-read-server-identification /dev/tcpin rfc))

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
             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-read-client-identification /dev/tcpin rfc))

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

    (let ghostcat : Void ([rekex : (U SSH-Kex (Pairof SSH-Kex (Pairof Integer Bytes)) False) #false]
                          [algorithms : (Option SSH-Transport-Algorithms) #false]
                          [kexinit : SSH-MSG-KEXINIT kexinit]
                          [newkeys : Maybe-Newkeys (make-ssh-parcel ($ssh-payload-capacity rfc))]
                          [inflights : (Option (Listof SSH-Message)) #false] ; to reduce args, #false => |we haven't sent kexinit|
                          [incoming : Integer rekex-traffic]
                          [outgoing : Integer rekex-traffic]
                          [authenticated : Boolean #false])
      (define evt : Any
        (cond [(and (not rekex) (or (>= incoming rekex-traffic) (>= outgoing rekex-traffic))) kexinit]
              [else (sync/enable-break /dev/sshin /dev/tcpin)]))
      
      (cond [(tcp-port? evt)
             (define-values (msg payload traffic)
               (ssh-read-transport-message /dev/tcpin rfc newkeys
                                           (cond [(not rekex) #false]
                                                 [(ssh-kex? rekex) (ssh-kex-name rekex)]
                                                 [else (ssh-kex-name (car rekex))])))
             
             (define maybe-rekex : Any
               (cond [(not msg) (ssh-deliver-message payload /dev/sshout authenticated)]
                     [(ssh-ignored-incoming-message? msg) (void)]
                     [(and rekex #| coincide with |# algorithms) 
                      (void)]
                     
                     [(ssh:msg:kexinit? msg)
                      (unless (list? inflights) (ssh-write-message /dev/tcpout kexinit rfc newkeys))
                      (cond [(and server?) (ssh-kex-instantiate/server kexinit msg rfc payload)]
                            [else (let-values ([(kex-self req) (ssh-kex-instantiate/client kexinit msg rfc newkeys payload)])
                                    kex-self)])]
                     
                     [(and (not authenticated) (ssh:msg:service:request? msg))
                      (define service : Symbol (ssh:msg:service:request-name msg))
                      (thread-send self (cond [(and server? (eq? service 'ssh-userauth)) (ssh-service-accept-message service)]
                                              [else (make-ssh:disconnect:service:not:available #:source ssh-transport-loop (ssh-service-reject-description service))]))]
                     
                     [else (write-special msg /dev/sshout)]))
             
             (let ([incoming++ (+ incoming traffic)])
               (cond [(ssh-kex? maybe-rekex) (ghostcat maybe-rekex algorithms kexinit newkeys (or inflights null) incoming++ outgoing authenticated)]
                     [else (ghostcat rekex algorithms kexinit newkeys inflights incoming++ outgoing authenticated)]))]
            
            [(ssh-message? evt)
             (if (not rekex)
                 (let ([traffic (ssh-write-message /dev/tcpout evt rfc newkeys)])
                   (if (ssh:msg:kexinit? evt)
                       (ghostcat rekex algorithms evt newkeys null #|we have sent kexinit|# incoming (+ outgoing traffic) authenticated)
                       (ghostcat rekex algorithms kexinit newkeys inflights incoming (+ outgoing traffic) (or authenticated (ssh:msg:userauth:success? evt)))))
                 (if (ssh-kex-transparent-message? evt)
                     (let ([traffic (ssh-write-message /dev/tcpout evt rfc newkeys)])
                       (ghostcat rekex algorithms kexinit newkeys inflights incoming (+ outgoing traffic) authenticated))
                     (ghostcat rekex algorithms kexinit newkeys (if (list? inflights) (cons evt inflights) (list evt)) incoming outgoing authenticated)))]
            
            [(and (pair? evt) (ssh-newkeys? (car evt)) (exact-nonnegative-integer? (cdr evt)))
             (when (ssh-parcel? newkeys) ; the first key exchange, tell client the session identity
               (write-special (ssh-newkeys-identity (car evt)) /dev/sshout))
             (ghostcat #false algorithms kexinit (car evt) inflights 0 (cdr evt) authenticated)]
            
            [else ; maybe the application want to make jokes
             (define traffic : Integer (ssh-write-message /dev/tcpout (make-ssh:msg:ignore #:data (format "~s" evt)) rfc newkeys))
             (ghostcat rekex algorithms kexinit newkeys inflights incoming (+ outgoing traffic) authenticated)]))))

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
