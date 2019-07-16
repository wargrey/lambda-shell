#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)
(require racket/string)

(require "transport/identification.rkt")
(require "transport/message.rkt")
(require "transport/kex.rkt")
(require "transport/newkeys.rkt")
(require "transport/prompt.rkt")
(require "transport/stdio.rkt")

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
   [port-number : Index]
   [subcustodian : Custodian]
   [sshcs : (Async-Channelof (List Custodian Input-Port Output-Port))])
  #:type-name SSH-Listener)

(struct ssh-port ssh-transport
  ([peer-name : Symbol]
   [identity : Bytes]
   [ghostcat : Thread]
   [sshin : (SSH-Stdin Port)])
  #:type-name SSH-Port)

(define-type SSH-Userauth-State (U 'authentic 'authenticating 'initial))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define sshc-ghostcat : (-> (SSH-Stdout Port) String String Natural SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification hostname port kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-deliver-error e /dev/sshout))])
             (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
             (define parcel : SSH-Parcel (make-ssh-parcel ($ssh-payload-capacity rfc) (ssh-mac-capacity kexinit)))

             (ssh-write-text /dev/tcpout identification)
             
             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT)
               (ssh-prompt #false
                           (λ [] (ssh-read-server-identification /dev/tcpin rfc))
                           (λ [[eof-msg : SSH-MSG-DISCONNECT]] eof-msg)))

             (ssh-stdout-propagate /dev/sshout peer)

             (if (ssh-message? peer)
                 (ssh-write-plain-message /dev/tcpout peer rfc parcel)
                 (ssh-prompt (current-peer-name)
                             (λ [] (ssh-transport-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit identification (ssh-identification-raw peer) parcel rfc #false))
                             /dev/sshout)))))))

(define sshd-ghostcat : (-> (SSH-Stdout Port) String Input-Port Output-Port SSH-MSG-KEXINIT SSH-Configuration Thread)
  (lambda [/dev/sshout identification /dev/tcpin /dev/tcpout kexinit rfc]
    (thread
     (λ [] (with-handlers ([exn? (λ [[e : exn]] (ssh-deliver-error e /dev/sshout))])
             (define parcel : SSH-Parcel (make-ssh-parcel ($ssh-payload-capacity rfc) (ssh-mac-capacity kexinit)))

             (ssh-write-text /dev/tcpout identification)

             (define peer : (U SSH-Identification SSH-MSG-DISCONNECT)
               (ssh-prompt #false
                           (λ [] (ssh-read-client-identification /dev/tcpin rfc))
                           (λ [[eof-msg : SSH-MSG-DISCONNECT]] eof-msg)))

             (ssh-stdout-propagate /dev/sshout peer)

             (if (ssh-message? peer)
                 (ssh-write-plain-message /dev/tcpout peer rfc parcel)
                 (ssh-prompt (current-peer-name)
                             (λ [] (ssh-transport-loop /dev/tcpin /dev/tcpout /dev/sshout kexinit (ssh-identification-raw peer) identification parcel rfc #true))
                             /dev/sshout)))))))

(define ssh-transport-loop : (-> Input-Port Output-Port (SSH-Stdout Port) SSH-MSG-KEXINIT String String SSH-Parcel SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit Vc Vs parcel rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (define rekex-traffic : Natural ($ssh-rekex-traffic rfc))
    (define self : Thread (current-thread))

    (define id-handshake-await : Any (sync/enable-break /dev/sshin))
    (when (ssh-message? id-handshake-await)
      (ssh-write-plain-message /dev/tcpout id-handshake-await rfc parcel))
    
    (define newkeys : SSH-Newkeys (ssh-transport-negotiate-newkeys /dev/tcpin /dev/tcpout /dev/sshout kexinit parcel Vc Vs rfc server?))
    (define-values (incoming-traffic outgoing-traffic) (ssh-transport-userauth-barrier /dev/tcpin /dev/tcpout /dev/sshin /dev/sshout newkeys rfc server?))
    
    (let service : Void ([rekex : (U SSH-Kex False) #false]
                         [rekexing : (Option SSH-Kex-Process) #false]
                         [kexinit : SSH-MSG-KEXINIT kexinit]
                         [newkeys : SSH-Newkeys newkeys]
                         [sthgilfni : (Option (Listof SSH-Message)) #false] ; to reduce args, #false => |we haven't sent kexinit|
                         [incoming-traffic : Integer incoming-traffic]
                         [outgoing-traffic : Integer outgoing-traffic])
      (define datum : Any
        (cond [(or (>= incoming-traffic rekex-traffic) (>= outgoing-traffic rekex-traffic)) kexinit]
              [else (sync/enable-break /dev/sshin /dev/tcpin)]))
      
      (cond [(tcp-port? datum)
             (define-values (msg payload traffic) (ssh-read-cipher-transport-message /dev/tcpin rfc newkeys (and rekex (ssh-kex-name rekex))))
             (define incoming++ : Integer (+ incoming-traffic traffic))
             (define step : (-> Void) (λ [] (service rekex rekexing kexinit newkeys sthgilfni incoming++ outgoing-traffic)))
             
             (cond [(not msg)
                    (cond [(not (ssh-authentication-payload? payload)) (ssh-stdout-propagate /dev/sshout payload) (step)]
                          [else (service rekex rekexing kexinit newkeys sthgilfni incoming++
                                         (+ (ssh-write-cipher-message /dev/tcpout (ssh-ignore-message datum) rfc newkeys) outgoing-traffic))])]

                   [(ssh-ignored-incoming-message? msg) (step)]
                   
                   [(and rekex #| coincide with |# rekexing)
                    (define maybe-newkeys : (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys) (rekexing rekex msg))
                    (if (pair? maybe-newkeys)
                        (let-values ([(kex-self reply) (values (car maybe-newkeys) (cdr maybe-newkeys))])
                          (ssh-write-cipher-message /dev/tcpout reply rfc newkeys)
                          (service kex-self rekexing kexinit newkeys sthgilfni incoming++ outgoing-traffic))
                        (let ([session : Bytes (ssh-newkeys-identity maybe-newkeys)])
                          (unless (not server?) ; client's SSH:NEWKESY is sent during the kexing
                            (ssh-write-cipher-message /dev/tcpout SSH:NEWKEYS rfc newkeys))

                          (let send-inflights ([inflights : (Listof SSH-Message) (if (list? sthgilfni) (reverse sthgilfni) null)]
                                               [flights-outgoing : Integer 0])
                            (cond [(null? inflights) (service #false #false kexinit maybe-newkeys #false 0 flights-outgoing)]
                                  [else (let ([traffic (ssh-write-cipher-message /dev/tcpout (car inflights) rfc maybe-newkeys)])
                                          (send-inflights (cdr inflights) (+ outgoing-traffic traffic)))]))))]
                   
                   [(ssh:msg:kexinit? msg)
                    (unless (list? sthgilfni) (ssh-write-cipher-message /dev/tcpout kexinit rfc newkeys))
                    (define maybe-kex-ing : (U (Pairof SSH-Kex SSH-Kex-Process) SSH-MSG-DISCONNECT)
                      (ssh-key-exchange kexinit msg rfc newkeys Vc Vs payload server? /dev/tcpout))
                    (cond [(ssh:msg:disconnect? maybe-kex-ing) (void (ssh-write-cipher-message /dev/tcpout maybe-kex-ing rfc newkeys))]
                          [else (service (car maybe-kex-ing) (cdr maybe-kex-ing) kexinit newkeys (or sthgilfni null) 0 0)])]

                   [else (ssh-stdout-propagate /dev/sshout msg) (step)])]
            
            [(ssh-message? datum)
             (if (not rekex)
                 (let ([traffic (ssh-write-cipher-message /dev/tcpout datum rfc newkeys)])
                   (if (ssh:msg:kexinit? datum)
                       (service rekex rekexing datum newkeys null #|we have sent kexinit|# 0 0)
                       (service rekex rekexing kexinit newkeys sthgilfni incoming-traffic (+ outgoing-traffic traffic))))
                 (if (ssh-kex-transparent-message? datum)
                     (let ([traffic (ssh-write-cipher-message /dev/tcpout datum rfc newkeys)])
                       (service rekex rekexing kexinit newkeys sthgilfni incoming-traffic (+ outgoing-traffic traffic)))
                     (service rekex rekexing kexinit newkeys (if (list? sthgilfni) (cons datum sthgilfni) (list datum)) incoming-traffic outgoing-traffic)))]
            
            [else ; applications/services have their rights to joke
             (service rekex rekexing kexinit newkeys sthgilfni incoming-traffic
                      (+ outgoing-traffic (ssh-write-cipher-message /dev/tcpout (ssh-ignore-message datum) rfc newkeys)))]))))

(define ssh-transport-negotiate-newkeys : (-> Input-Port Output-Port (SSH-Stdout Port) SSH-MSG-KEXINIT SSH-Parcel String String SSH-Configuration Boolean SSH-Newkeys)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit parcel Vc Vs rfc server?]
    ; The SSH-Port will keep waiting for the session id,
    ; so this is no chance to send in-flight messages.
    
    (ssh-write-plain-message /dev/tcpout kexinit rfc parcel)

    (define newkeys : SSH-Newkeys
      (let negotiate : SSH-Newkeys ([kex : (U SSH-Kex False) #false]
                                    [kexing : (Option SSH-Kex-Process) #false])
        (define await : Any (sync/enable-break /dev/tcpin))
        (define-values (msg payload _) (ssh-read-plain-transport-message /dev/tcpin rfc parcel (and kex (ssh-kex-name kex))))
        
        (cond [(not msg) (ssh-write-plain-message /dev/tcpout (ssh-ignore-message payload) rfc parcel) (negotiate kex kexing)]
              [(ssh-ignored-incoming-message? msg) (negotiate kex kexing)]
              
              [(and kex #| coincide with |# kexing)
               (define maybe-newkeys : (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys) (kexing kex msg))
               (if (ssh-newkeys? maybe-newkeys)
                   (and (unless (not server?) ; client's SSH:NEWKESY is sent during the kexing
                          (ssh-write-plain-message /dev/tcpout SSH:NEWKEYS rfc parcel))
                        maybe-newkeys)
                   (let-values ([(kex-self reply) (values (car maybe-newkeys) (cdr maybe-newkeys))])
                     (ssh-write-plain-message /dev/tcpout reply rfc parcel)
                     (negotiate kex-self kexing)))]
              
              [(ssh:msg:kexinit? msg)
               (define maybe-kex-ing : (U (Pairof SSH-Kex SSH-Kex-Process) SSH-MSG-DISCONNECT)
                 (ssh-key-exchange kexinit msg rfc parcel Vc Vs payload server? /dev/tcpout))
               (cond [(ssh:msg:disconnect? maybe-kex-ing) (ssh-write-plain-message /dev/tcpout maybe-kex-ing rfc parcel) (negotiate kex kexing)]
                     [else (negotiate (car maybe-kex-ing) (cdr maybe-kex-ing))])]
              
              [else (ssh-write-plain-message /dev/tcpout (ssh-ignore-message msg) rfc parcel) (negotiate kex kexing)])))

    (ssh-stdout-propagate /dev/sshout (ssh-newkeys-identity newkeys))

    newkeys))

(define ssh-transport-userauth-barrier : (-> Input-Port Output-Port (Evtof Any) (SSH-Stdout Port) SSH-Newkeys SSH-Configuration Boolean (Values Natural Natural))
  (lambda [/dev/tcpin /dev/tcpout /dev/sshin /dev/sshout newkeys rfc server?]
    ; This routine does not do authenticating, it just watches the start and end of the authenticating
    ;   so that messages of super services will not be propagated too early.
    
    ; Besides, you don't want to follow the first kexing with just another one.
    (let userauth : (values Natural Natural) ([incoming-traffic : Natural 0]
                                              [outgoing-traffic : Natural 0]
                                              [authenticating? : Boolean #false])
      (define datum : Any (sync/enable-break /dev/sshin /dev/tcpin))
      
      (cond [(tcp-port? datum)
             (define-values (msg payload traffic) (ssh-read-cipher-transport-message /dev/tcpin rfc newkeys #false))
             (define incoming++ : Natural (+ incoming-traffic traffic))

             (cond [(not msg)
                    (if (and authenticating? (ssh-authentication-payload? payload))
                        (and (ssh-stdout-propagate /dev/sshout payload)
                             (if (and (not server?) (= (ssh-message-payload-number payload) (ssh-message-number SSH:USERAUTH:SUCCESS)))
                                 (values incoming++ outgoing-traffic)
                                 (userauth incoming++ outgoing-traffic authenticating?)))
                        (userauth incoming++
                                  (+ (ssh-write-cipher-message /dev/tcpout (ssh-ignore-message payload) rfc newkeys) outgoing-traffic)
                                  authenticating?))]
                   
                   [(ssh-ignored-incoming-message? msg) (userauth incoming++ outgoing-traffic authenticating?)]
                   
                   [(ssh:msg:service:request? msg)
                    (define service : Symbol (ssh:msg:service:request-name msg))
                    (define response : SSH-Message
                      (cond [(and server? (eq? service 'ssh-userauth)) (make-ssh:msg:service:accept #:name service)]
                            [else (make-ssh:disconnect:service:not:available #:source ssh-transport-userauth-barrier
                                                                             (ssh-service-reject-description service))]))
                    (userauth incoming++ (+ (ssh-write-cipher-message /dev/tcpout response rfc newkeys) outgoing-traffic) #true)]

                   [(ssh:msg:service:accept? msg)
                    (define service : Symbol (ssh:msg:service:accept-name msg))
                    (cond [(not (and (not server?) (eq? service 'ssh-userauth))) (userauth incoming++ outgoing-traffic authenticating?)]
                          [else (ssh-stdout-propagate /dev/sshout msg) (userauth incoming++ outgoing-traffic #true)])]

                   [else (userauth incoming++
                                   (+ (ssh-write-cipher-message /dev/tcpout (ssh-ignore-message msg) rfc newkeys) outgoing-traffic)
                                   authenticating?)])]
            
            [(or (ssh-generic-message? datum) (ssh-authentication-message? datum))
             (define outgoing++ : Natural (+ (ssh-write-cipher-message /dev/tcpout datum rfc newkeys) outgoing-traffic))
             (cond [(and server? authenticating? (ssh:msg:userauth:success? datum)) (values incoming-traffic outgoing++)]
                   [else (userauth incoming-traffic outgoing++ authenticating?)])]
            
            [else ; please no joking at this moment
             (userauth incoming-traffic
                       (+ (ssh-write-cipher-message /dev/tcpout (ssh-ignore-message datum) rfc newkeys) outgoing-traffic)
                       authenticating?)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-service-accept-message : (-> Symbol SSH-MSG-SERVICE-ACCEPT)
  (lambda [service]
    (make-ssh:msg:service:accept #:name service)))

(define ssh-ignore-message : (-> Any SSH-MSG-IGNORE)
  (lambda [payload]
    (make-ssh:msg:ignore #:data (format "~s" payload))))

(define ssh-unimplemented-message : (-> (U Bytes SSH-Message) SSH-MSG-UNIMPLEMENTED)
  (lambda [msg]
    (make-ssh:msg:unimplemented #:number (if (bytes? msg) (bytes-ref msg 0) (ssh-message-number msg)))))

(define ssh-service-reject-description : (-> Symbol String)
  (lambda [service]
    (format "service '~a' not available" service)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-pull-datum : (All (a) (-> (SSH-Stdin Port) Index (-> Any Boolean : a) Procedure (U a SSH-MSG-DISCONNECT)))
  (lambda [/dev/sshin timeout ? func]
    (define datum-evt : (Evtof Any) ((inst ssh-stdin-evt Any) /dev/sshin))
    (define maybe-datum : Any
      (cond [(= timeout 0) (sync/enable-break datum-evt)]
            [else (sync/timeout/enable-break timeout datum-evt)]))

    (cond [(not maybe-datum) (make-ssh:disconnect:connection:lost "timeout")]
          [(ssh:msg:disconnect? maybe-datum) maybe-datum]
          [else (assert maybe-datum ?)])))

(define ssh-deliver-error : (-> exn (SSH-Stdout Port) Void)
  (lambda [e /dev/sshout]
    (define eof-msg : SSH-MSG-DISCONNECT
      (make-ssh:disconnect:reserved #:source ssh-deliver-error "~a: ~a: ~a" (current-peer-name) (object-name e)
                                    (string-trim (call-with-output-string
                                                     (λ [[/dev/strout : Output-Port]]
                                                       (parameterize ([current-error-port /dev/strout])
                                                         ((error-display-handler) (exn-message e) e)))))))

    (ssh-log-message 'error #:with-peer-name? #false (ssh:msg:disconnect-description eof-msg))
    (ssh-stdout-propagate #:level 'error /dev/sshout eof-msg (ssh:msg:disconnect-description eof-msg))))

(define ssh-throw-disconnection : (->* (SSH-MSG-DISCONNECT) (#:level (Option Log-Level)) Nothing)
  (lambda [msg #:level [level 'error]]
    (define message : String (format "~a: ~a" (ssh:msg:disconnect-reason msg) (ssh:msg:disconnect-description msg)))

    (unless (not level)
      (ssh-log-message level message))
    
    (raise (make-exn:fail:network message (current-continuation-marks)))))
