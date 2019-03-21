#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-Port SSH-Listener)

(require racket/tcp)
(require racket/port)

(require "digitama/transport/identification.rkt")
(require "digitama/transport/message.rkt")
(require "digitama/transport.rkt")
(require "digitama/configuration.rkt")

(require "digitama/diagnostics.rkt")
(require "digitama/stdin.rkt")

(require "assignment.rkt")

(define ssh-connect : (-> String Natural [#:custodian Custodian] [#:configuration SSH-Configuration] [#:kexinit SSH-MSG-KEXINIT] SSH-Port)
  (lambda [hostname port #:custodian [root (make-custodian)] #:configuration [rfc (make-ssh-configuration)] #:kexinit [kexinit (make-ssh:msg:kexinit)]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian])
      (define server-name : String (format "~a:~a" hostname port))
      (ssh-log-message 'debug "connecting to ~a:~a" hostname port)
      
      (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 server-name server-name))
      (define sshc : Thread (sshc-ghostcat /dev/sshout hostname port rfc))

      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
        (define server-id : SSH-Identification (ssh-read-special /dev/sshin ($ssh-timeout rfc) ssh-identification? 'ssh-connect))
        (ssh-log-message 'debug "server identification string: ~a" (ssh-identification-raw server-id))
        (thread-send sshc kexinit)
        (SSH-Port root sshc-custodian rfc sshc /dev/sshin server-name)))))

(define ssh-listen : (->* (Natural) (Index #:custodian Custodian #:hostname (Option String) #:kexinit SSH-MSG-KEXINIT #:configuration SSH-Configuration) SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:hostname [hostname #false]
                #:kexinit [kexinit (make-ssh:msg:kexinit)] #:configuration [rfc (make-ssh-configuration)]]
    (define listener-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian listener-custodian])
      (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
      (define-values (id idsize) (ssh-identification-string rfc))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses sshd #true))
      (ssh-log-message 'debug "listening on ~a:~a" local-name local-port)
      (SSH-Listener root listener-custodian rfc sshd (substring id 0 idsize) kexinit
                    (format "~a:~a" local-name local-port) local-port))))

(define ssh-accept : (-> SSH-Listener [#:custodian Custodian] SSH-Port)
  (lambda [listener #:custodian [root (make-custodian)]]
    (define rfc : SSH-Configuration (ssh-transport-preference listener))
    (define sshd-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshd-custodian])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break (ssh-listener-watchdog listener)))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
      (ssh-log-message 'debug "accepted ~a:~a" remote-name remote-port)

      (define client-name : String (format "~a:~a" remote-name remote-port))
      (define-values (/dev/sshin /dev/sshout) (make-pipe-with-specials 1 client-name client-name))
      (define sshd : Thread (sshd-ghostcat /dev/sshout (ssh-listener-identification listener) /dev/tcpin /dev/tcpout rfc))

      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
        (define client-id : SSH-Identification (ssh-read-special /dev/sshin ($ssh-timeout rfc) ssh-identification? 'ssh-accept))
        (ssh-log-message 'debug "client identification string: ~a" (ssh-identification-raw client-id))
        
        (unless (= (ssh-identification-protoversion client-id) ($ssh-protoversion rfc))
          (ssh-sync-disconnect sshd 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)
          (throw exn:ssh:identification /dev/tcpin 'ssh-accept
                 "incompatible protoversion: ~a" (ssh-identification-protoversion client-id)))

        (thread-send sshd (ssh-listener-kexinit listener))
        (SSH-Port root sshd-custodian rfc sshd /dev/sshin client-name)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-port-wait : (-> SSH-Port Void)
  (lambda [self]
    (thread-wait (ssh-port-ghostcat self))))

(define ssh-port-send : (-> SSH-Port Any Void)
  (lambda [self payload]
    (cond [(ssh-message? payload) (thread-send (ssh-port-ghostcat self) payload)]
          [else (ssh-port-send self (make-ssh:msg:ignore #:data (format "~s" payload)))])))

(define ssh-port-debug : (->* (SSH-Port Any) (Boolean) Void)
  (lambda [self payload [display? #false]]
    (ssh-port-send self (make-ssh:msg:debug #:display? display? #:message (format "~a" payload)))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-custodian : (-> (U SSH-Listener SSH-Port) Custodian)
  (lambda [self]
    (ssh-transport-custodian self)))

(define ssh-managed-list : (-> (U SSH-Listener SSH-Port) (Listof Any))
  (lambda [self]
    (define root : Custodian (ssh-transport-root self))
    (define (unbox [child : Any]) : Any
      (cond [(not (custodian? child)) child]
            [else (unbox (custodian-managed-list child root))]))
    (map unbox (custodian-managed-list (ssh-transport-custodian self) root))))