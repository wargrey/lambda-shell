#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-Port SSH-Listener)
(provide ssh-transport? ssh-port? ssh-listener?)
(provide ssh-port-peer-name ssh-transport-preference)

(require racket/tcp)
(require racket/port)

(require typed/racket/unsafe)

(unsafe-require/typed racket/base
                      [read-byte-or-special (-> Input-Port SSH-Datum)])

(require "message.rkt")
(require "configuration.rkt")

(require "digitama/transport.rkt")
(require "digitama/diagnostics.rkt")

(require "digitama/transport/identification.rkt")
(require "digitama/message/transport.rkt")

;; register builtin assignments for algorithms
(require "digitama/assignment/kex.rkt")
(require "digitama/assignment/hostkey.rkt")
(require "digitama/assignment/mac.rkt")
(require "digitama/assignment/cipher.rkt")
(require "digitama/assignment/compression.rkt")

(define-type SSH-EOF (U SSH-MSG-DISCONNECT exn))
(define-type SSH-Datum (U SSH-Message SSH-EOF Bytes))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connect : (-> String Natural [#:custodian Custodian] [#:logger Logger] [#:configuration SSH-Configuration] [#:kexinit SSH-MSG-KEXINIT] SSH-Port)
  (lambda [hostname port #:custodian [root (make-custodian)] #:logger [logger (make-logger 'λsh:sshc (current-logger))]
                    #:configuration [rfc (make-ssh-configuration)] #:kexinit [kexinit (make-ssh:msg:kexinit)]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian]
                   [current-logger logger])
      (define server-name : Symbol (string->symbol (format "~a:~a" hostname port)))
      (ssh-log-message 'debug "connecting to ~a" server-name)

      (parameterize ([current-peer-name server-name])
        (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 server-name server-name))
        (define identification : String (ssh-identification-string rfc))
        (ssh-log-message 'debug "local identification string: ~a" identification)       
        (define sshc : Thread (sshc-ghostcat /dev/sshout identification hostname port kexinit rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
          (define server-id : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-pull-special /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-connect))

          (cond [(ssh-message? server-id) (thread-send sshc server-id)]
                [else (ssh-log-message 'debug "server[~a] identification string: ~a" server-name (ssh-identification-raw server-id))])

          (define session-id : (U Bytes SSH-MSG-DISCONNECT) (ssh-pull-special /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect))
          (ssh-port sshc-custodian rfc logger server-name (if (bytes? session-id) session-id #"") sshc /dev/sshin))))))

(define ssh-listen : (->* (Natural)
                          (Index #:custodian Custodian #:logger Logger #:hostname (Option String) #:kexinit SSH-MSG-KEXINIT #:configuration SSH-Configuration)
                          SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:logger [logger (make-logger 'λsh:sshd (current-logger))] #:hostname [hostname #false]
                #:kexinit [kexinit (make-ssh:msg:kexinit)] #:configuration [rfc (make-ssh-configuration)]]
    (define listener-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian listener-custodian]
                   [current-logger logger])
      (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses sshd #true))
      (define identification : String (ssh-identification-string rfc))

      (ssh-log-message 'debug "listening on ~a:~a" local-name local-port)
      (ssh-log-message 'debug "local identification string: ~a" identification)
      (ssh-listener listener-custodian rfc logger sshd identification kexinit
                    (string->symbol (format "~a:~a" local-name local-port)) local-port))))

(define ssh-accept : (-> SSH-Listener [#:custodian Custodian] SSH-Port)
  (lambda [listener #:custodian [root (make-custodian)]]
    (define rfc : SSH-Configuration (ssh-transport-preference listener))
    (define sshd-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshd-custodian]
                   [current-logger (ssh-transport-logger listener)])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break (ssh-listener-watchdog listener)))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
      (define client-name : Symbol (string->symbol (format "~a:~a" remote-name remote-port)))
      (ssh-log-message 'debug "accepted ~a" client-name #:with-peer-name? #false)
      
      (parameterize ([current-peer-name client-name])
        (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 client-name client-name))
        (define kexinit : SSH-MSG-KEXINIT  (ssh-listener-kexinit listener))
        (define sshd : Thread (sshd-ghostcat /dev/sshout (ssh-listener-identification listener) /dev/tcpin /dev/tcpout kexinit rfc))
        
        (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
          (define client-id : (U SSH-Identification SSH-MSG-DISCONNECT) (ssh-pull-special /dev/sshin ($ssh-timeout rfc) ssh-identification? ssh-accept))

          (cond [(ssh-message? client-id) (thread-send sshd client-id)]
                [else (ssh-log-message 'debug "client[~a] identification string: ~a" client-name (ssh-identification-raw client-id))])

          (define session-id : (U Bytes SSH-MSG-DISCONNECT) (ssh-pull-special /dev/sshin ($ssh-timeout rfc) bytes? ssh-connect))
          (ssh-port sshd-custodian rfc (current-logger) client-name (if (bytes? session-id) session-id #"") sshd /dev/sshin))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-listener-evt : (-> SSH-Listener (Evtof SSH-Listener))
  (lambda [self]
    (wrap-evt (ssh-listener-watchdog self)
              (λ _ self))))

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

(define ssh-port-write : (-> SSH-Port Any Void)
  (lambda [self payload]
    (thread-send (ssh-port-ghostcat self) payload)))

(define ssh-port-debug : (->* (SSH-Port Any) (Boolean) Void)
  (lambda [self payload [display? #false]]
    (ssh-port-write self (make-ssh:msg:debug #:display? display? #:message (format "~a" payload)))))

(define ssh-port-request-service : (-> SSH-Port Symbol Void)
  (lambda [self service]
    (ssh-port-write self (make-ssh:msg:service:request #:name service))))

(define ssh-port-reject-service : (-> SSH-Port Symbol Void)
  (lambda [self service]
    (ssh-shutdown self 'SSH-DISCONNECT-SERVICE-NOT-AVAILABLE
                  (ssh-service-reject-description service))))

(define ssh-port-wait : (-> SSH-Port [#:kill? Boolean] Void)
  (lambda [self #:kill? [kill? #false]]
    (unless (not kill?)
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
     (thread-send (ssh-port-ghostcat self) (make-ssh:msg:disconnect #:reason reason #:description (or description (void))))
     (ssh-port-wait self #:kill? #false)]))

(define ssh-eof? : (-> Any Boolean : #:+ SSH-EOF)
  (lambda [datum]
    (or (ssh:msg:disconnect? datum)
        (exn? datum))))

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
