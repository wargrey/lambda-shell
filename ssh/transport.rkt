#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-Port SSH-Listener)
(provide ssh-transport? ssh-port? ssh-listener?)
(provide ssh-port-peer-name ssh-transport-preference)

(require racket/tcp)
(require racket/port)
(require typed/racket/async-channel)

(require "message.rkt")
(require "configuration.rkt")

(require "digitama/stdio.rkt")
(require "digitama/diagnostics.rkt")
(require "digitama/transport.rkt")
(require "digitama/transport/identification.rkt")
(require "digitama/message/transport.rkt")

;; register builtin assignments for algorithms
(require "digitama/assignment/kex.rkt")
(require "digitama/assignment/hostkey.rkt")
(require "digitama/assignment/mac.rkt")
(require "digitama/assignment/cipher.rkt")
(require "digitama/assignment/compression.rkt")

(define-type SSH-EOF SSH-MSG-DISCONNECT)
(define-type SSH-Datum (U SSH-Message SSH-EOF Bytes))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connect : (-> String Natural [#:custodian Custodian] [#:logger Logger] [#:configuration SSH-Configuration] [#:kexinit SSH-MSG-KEXINIT] SSH-Port)
  (lambda [hostname port #:custodian [root (make-custodian)] #:logger [logger (make-logger 'λsh:sshc (current-logger))]
                    #:configuration [rfc (make-ssh-configuration)] #:kexinit [kexinit (make-ssh:msg:kexinit)]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian]
                   [current-logger logger])
      (define server-name : Symbol (string->symbol (format "~a:~a" hostname port)))
      (ssh-log-message 'info "connecting to ~a" server-name)

      (parameterize ([current-peer-name server-name])
        (define-values (/dev/sshin /dev/sshout) (make-ssh-stdio server-name))
        (define-values (/dev/srvin /dev/srvout) (make-ssh-stdio server-name))
        (define identification : String (ssh-identification-string rfc))
        (ssh-log-message 'debug "local identification string: ~a" identification)       
        (define sshc : Thread (sshc-ghostcat /dev/sshout /dev/srvout identification hostname port kexinit rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
          (define server-id : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-pull-datum /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-connect))

          (if (ssh-message? server-id)
              (ssh-throw-disconnection server-id #:level #false)
              (thread-send sshc (ssh-log-message 'debug #:with-peer-name? #false "server[~a] identification string: ~a"
                                                 server-name (ssh-identification-raw server-id))))

          (let ([session (ssh-pull-datum /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect)])
            (cond [(ssh-message? session) (ssh-throw-disconnection session #:level #false)]
                  [else (ssh-port sshc-custodian rfc logger server-name session sshc
                                  /dev/sshin /dev/srvin)])))))))

(define ssh-listen : (->* (Natural)
                          (Index #:custodian Custodian #:client-custodian Custodian #:logger Logger
                                 #:hostname (Option String) #:kexinit SSH-MSG-KEXINIT #:configuration SSH-Configuration)
                          SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:client-custodian [client-root (make-custodian)] #:logger [logger (make-logger 'λsh:sshd (current-logger))]
                #:hostname [hostname #false] #:kexinit [kexinit (make-ssh:msg:kexinit)] #:configuration [rfc (make-ssh-configuration)]]
    (define listener-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian listener-custodian]
                   [current-logger logger])
      (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses sshd #true))
      (define identification : String (ssh-identification-string rfc))

      (ssh-log-message 'info "listening on ~a:~a" local-name local-port)
      (ssh-log-message 'debug "local identification string: ~a" identification)
      (ssh-listener listener-custodian rfc logger sshd identification kexinit
                    (string->symbol (format "~a:~a" local-name local-port)) local-port
                    client-root (make-async-channel)))))

(define ssh-accept : (-> SSH-Listener SSH-Port)
  (lambda [listener]
    (define rfc : SSH-Configuration (ssh-transport-preference listener))
    (define-values (sshd-custodian /dev/tcpin /dev/tcpout)
      (let* ([sshcs (ssh-listener-sshcs listener)]
             [pending (async-channel-try-get sshcs)]
             [pending (or pending (sync/enable-break (wrap-evt (ssh-listener-evt listener) (λ [_] (async-channel-get sshcs)))))])
        (values (car pending) (cadr pending) (caddr pending))))
    
    (parameterize ([current-custodian sshd-custodian]
                   [current-logger (ssh-transport-logger listener)])
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
      (define client-name : Symbol (string->symbol (format "~a:~a" remote-name remote-port)))
      (ssh-log-message 'info "client[~a] established a connection" client-name #:with-peer-name? #false)
      
      (parameterize ([current-peer-name client-name])
        (define-values (/dev/sshin /dev/sshout) (make-ssh-stdio client-name))
        (define-values (/dev/srvin /dev/srvout) (make-ssh-stdio client-name))
        (define kexinit : SSH-MSG-KEXINIT  (ssh-listener-kexinit listener))
        (define sshd : Thread (sshd-ghostcat /dev/sshout /dev/srvout (ssh-listener-identification listener) /dev/tcpin /dev/tcpout kexinit rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
          (define client-id : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-pull-datum /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-accept))

          (if (ssh-message? client-id)
              (ssh-throw-disconnection client-id #:level #false)
              (thread-send sshd (ssh-log-message 'debug #:with-peer-name? #false "client[~a] identification string: ~a"
                                                 client-name (ssh-identification-raw client-id))))

          (let ([session (ssh-pull-datum /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect)])
            (cond [(ssh-message? session) (ssh-throw-disconnection session #:level #false)]
                  [else (ssh-port sshd-custodian rfc (current-logger) client-name session sshd
                                  /dev/sshin /dev/srvin)])))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-listener-evt : (-> SSH-Listener (Evtof SSH-Listener))
  (lambda [self]
    (wrap-evt (ssh-listener-watchdog self)
              (λ [[sshd : TCP-Listener]]
                (parameterize ([current-custodian (make-custodian (ssh-listener-subcustodian self))])
                  (let-values ([(/dev/tcpin /dev/tcpout) (tcp-accept/enable-break sshd)])
                    (async-channel-put (ssh-listener-sshcs self) (list (current-custodian) /dev/tcpin /dev/tcpout))
                    self))))))

(define ssh-port-datum-evt : (-> SSH-Port (Evtof SSH-Datum))
  (lambda [self]
    ((inst ssh-stdin-evt SSH-Datum)
     (ssh-port-sshin self))))

(define ssh-port-read : (-> SSH-Port SSH-Datum)
  (lambda [self]
    (sync/enable-break (ssh-port-datum-evt self))))

(define ssh-port-write : (-> SSH-Port Any Void)
  (lambda [self payload]
    (thread-send (ssh-port-ghostcat self) payload)))

(define ssh-port-debug : (->* (SSH-Port Any) (Boolean) Void)
  (lambda [self payload [display? #false]]
    (ssh-port-write self (make-ssh:msg:debug #:display? display? #:message (format "~a" payload)))))

(define ssh-port-ignore : (-> SSH-Port Any Void)
  (lambda [self garbage]
    (ssh-port-write self (ssh-ignore-message garbage))))

(define ssh-port-request-service : (-> SSH-Port Symbol [#:wait? Boolean] Void)
  (lambda [self service #:wait? [wait? #true]]
    (ssh-port-write self (make-ssh:msg:service:request #:name service))

    (unless (not wait?)
      (sync/enable-break (ssh-port-service-accept-evt self))
      (void))))

(define ssh-port-service-accept-evt : (-> SSH-Port (Evtof Symbol))
  (lambda [self]
    (wrap-evt ((inst ssh-stdin-evt SSH-MSG-SERVICE-ACCEPT) (ssh-port-srvin self))
              (λ [[msg : SSH-MSG-SERVICE-ACCEPT]] (ssh:msg:service:accept-name msg)))))

(define ssh-port-reject-service : (-> SSH-Port Symbol Void)
  (lambda [self service]
    (ssh-shutdown self 'SSH-DISCONNECT-SERVICE-NOT-AVAILABLE
                  (ssh-service-reject-description service))))

(define ssh-port-wait : (-> SSH-Port [#:abandon? Boolean] Void)
  (lambda [self #:abandon? [abandon? #false]]
    (unless (not abandon?)
      (custodian-shutdown-all (ssh-transport-custodian self)))
    
    (thread-wait (ssh-port-ghostcat self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-shutdown : (case-> [(U SSH-Listener SSH-Port) -> Void]
                               [SSH-Port (U Symbol String) -> Void]
                               [SSH-Port Symbol (Option String) -> Void])
  (case-lambda
    [(self)
     (if (ssh-listener? self)
         (custodian-shutdown-all (ssh-transport-custodian self))
         (ssh-shutdown self 'SSH-DISCONNECT-BY-APPLICATION))]
    [(self reason)
     (if (string? reason)
         (ssh-shutdown self 'SSH-DISCONNECT-BY-APPLICATION reason)
         (ssh-shutdown self reason #false))]
    [(self reason description)
     (when (thread-running? (ssh-port-ghostcat self))
       (thread-send (ssh-port-ghostcat self)
                    (make-ssh:msg:disconnect #:reason reason #:description description)))
     (ssh-port-wait self #:abandon? #false)]))

(define ssh-eof? : (-> Any Boolean : #:+ SSH-EOF)
  (lambda [datum]
    (ssh:msg:disconnect? datum)))

(define ssh-port-session-identity : (-> SSH-Port Bytes)
  (lambda [self]
    (ssh-port-identity self)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-custodian : (-> SSH-Transport Custodian)
  (lambda [self]
    (ssh-transport-custodian self)))

(define ssh-logger : (-> SSH-Transport Logger)
  (lambda [self]
    (ssh-transport-logger self)))
