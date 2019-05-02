#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-Port SSH-Listener)

(require racket/tcp)
(require racket/port)

(require typed/racket/unsafe)

(unsafe-require/typed racket/base
                      [read-byte-or-special (-> Input-Port SSH-Datum)])

(require "digitama/transport/identification.rkt")
(require "digitama/transport.rkt")
(require "digitama/diagnostics.rkt")

(require "message.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;;; register builtin assignments for algorithms
(require "digitama/assignment/diffie-hellman.rkt")
(require "digitama/assignment/hostkey.rkt")
(require "digitama/assignment/mac.rkt")
(require "digitama/assignment/cipher.rkt")
(require "digitama/assignment/compression.rkt")

(define-type SSH-Datum (U SSH-Message Bytes EOF exn))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connect : (-> String Natural [#:custodian Custodian] [#:logger Logger] [#:configuration SSH-Configuration] [#:kexinit SSH-MSG-KEXINIT] SSH-Port)
  (lambda [hostname port #:custodian [root (make-custodian)] #:logger [logger (make-logger 'λsh:sshc (current-logger))]
                    #:configuration [rfc (make-ssh-configuration)] #:kexinit [kexinit (make-ssh:msg:kexinit)]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian]
                   [current-logger logger])
      (define server-name : Symbol (string->symbol (format "${~a:~a}" hostname port)))
      (ssh-log-message 'debug "connecting to ~a" server-name)

      (parameterize ([current-peer-name server-name])
        (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 server-name server-name))
        (define identification : String (ssh-identification-string rfc))
        (ssh-log-message 'debug "local identification string: ~a" identification)       
        (define sshc : Thread (sshc-ghostcat /dev/sshout identification hostname port kexinit rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
          (define server-id : SSH-Identification (ssh-read-special /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-connect))
          (ssh-log-message 'debug "server[~a:~a] identification string: ~a" hostname port (ssh-identification-raw server-id))

          (define session-id : Bytes (ssh-read-special /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect))
          (ssh-port root sshc-custodian rfc logger session-id sshc /dev/sshin))))))

(define ssh-listen : (->* (Natural)
                          (Index #:custodian Custodian #:logger Logger #:hostname (Option String) #:kexinit SSH-MSG-KEXINIT #:configuration SSH-Configuration
                                 #:services (Listof Symbol) #:disable-reserved-services? Boolean)
                          SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:logger [logger (make-logger 'λsh:sshd (current-logger))] #:hostname [hostname #false]
                #:kexinit [kexinit (make-ssh:msg:kexinit)] #:configuration [rfc (make-ssh-configuration)]
                #:services [services null] #:disable-reserved-services? [disable-reserved-services? #false]]
    (define listener-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian listener-custodian]
                   [current-logger logger])
      (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses sshd #true))
      (define identification : String (ssh-identification-string rfc))
      (ssh-log-message 'debug "listening on ~a:~a" local-name local-port)
      (ssh-log-message 'debug "local identification string: ~a" identification)
      (ssh-listener root listener-custodian rfc logger sshd identification kexinit
                    (if (not disable-reserved-services?) (list* 'ssh-userauth 'ssh-connection services) services)
                    (format "~a:~a" local-name local-port) local-port))))

(define ssh-accept : (-> SSH-Listener [#:custodian Custodian] SSH-Port)
  (lambda [listener #:custodian [root (make-custodian)]]
    (define rfc : SSH-Configuration (ssh-transport-preference listener))
    (define sshd-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshd-custodian]
                   [current-logger (ssh-transport-logger listener)])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break (ssh-listener-watchdog listener)))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
      (define client-name : Symbol (string->symbol (format "${~a:~a}" remote-name remote-port)))
      (ssh-log-message 'debug "accepted ~a" client-name)
      
      (parameterize ([current-peer-name client-name])
        (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 client-name client-name))
        (define kexinit : SSH-MSG-KEXINIT  (ssh-listener-kexinit listener))
        (define sshd : Thread (sshd-ghostcat /dev/sshout (ssh-listener-identification listener)
                                             /dev/tcpin /dev/tcpout kexinit (ssh-listener-services listener) rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
          (define client-id : SSH-Identification (ssh-read-special /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-accept))
          (ssh-log-message 'debug "client[~a:~a] identification string: ~a" remote-name remote-port (ssh-identification-raw client-id))
          
          (unless (= (ssh-identification-protoversion client-id) ($ssh-protoversion rfc))
            (ssh-sync-disconnect sshd 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)
            (ssh-raise-identification-error ssh-accept
                                            "incompatible protoversion: ~a"
                                            (ssh-identification-protoversion client-id)))

          (define session-id : Bytes (ssh-read-special /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect))
          (ssh-port root sshd-custodian rfc (current-logger) session-id sshd /dev/sshin))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-port-datum-evt : (-> SSH-Port (Evtof SSH-Datum))
  (lambda [self]
    (wrap-evt (ssh-port-read-evt self)
              (λ _ (ssh-port-read self)))))

(define ssh-port-read-evt : (-> SSH-Port (Evtof Input-Port))
  (lambda [self]
    (ssh-port-sshin self)))

(define ssh-port-read : (-> SSH-Port SSH-Datum)
  (lambda [self]
    (read-byte-or-special (ssh-port-sshin self))))

(define ssh-port-send : (-> SSH-Port Any Void)
  (lambda [self payload]
    (cond [(ssh-message? payload) (thread-send (ssh-port-ghostcat self) payload)]
          [else (ssh-port-send self (make-ssh:msg:ignore #:data (format "~s" payload)))])))

(define ssh-port-debug : (->* (SSH-Port Any) (Boolean) Void)
  (lambda [self payload [display? #false]]
    (ssh-port-send self (make-ssh:msg:debug #:display? display? #:message (format "~a" payload)))))

(define ssh-port-wait : (-> SSH-Port [#:abandon? Boolean] Void)
  (lambda [self #:abandon? [abandon? #false]]
    (unless (not abandon?)
      (custodian-shutdown-all (ssh-transport-custodian self)))
    
    (thread-wait (ssh-port-ghostcat self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-shutdown : (case-> [SSH-Listener -> Void]
                               [SSH-Port SSH-Disconnection-Reason -> Void]
                               [SSH-Port SSH-Disconnection-Reason (Option String) -> Void])
  (case-lambda
    [(self) (custodian-shutdown-all (ssh-transport-custodian self))]
    [(self reason) (ssh-shutdown self reason #false)]
    [(self reason description)
     (ssh-sync-disconnect (ssh-port-ghostcat self) reason description)
     (custodian-shutdown-all (ssh-transport-custodian self))]))

(define ssh-port-session-identity : (-> SSH-Port Bytes)
  (lambda [self]
    (ssh-port-identity self)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-custodian : (-> (U SSH-Listener SSH-Port) Custodian)
  (lambda [self]
    (ssh-transport-custodian self)))

(define ssh-logger : (-> (U SSH-Listener SSH-Port) Logger)
  (lambda [self]
    (ssh-transport-logger self)))

(define ssh-managed-list : (-> (U SSH-Listener SSH-Port) (Listof Any))
  (lambda [self]
    (define root : Custodian (ssh-transport-root self))
    (define (unbox [child : Any]) : Any
      (cond [(not (custodian? child)) child]
            [else (unbox (custodian-managed-list child root))]))
    (map unbox (custodian-managed-list (ssh-transport-custodian self) root))))
