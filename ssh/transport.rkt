#lang typed/racket/base

(provide (all-defined-out))
(provide (rename-out [SSH-Listener-custodian ssh-listener-custodian]))

(require racket/tcp)
(require racket/port)

(require "digitama/transport/identification.rkt")
(require "digitama/transport.rkt")

(require "digitama/diagnostics.rkt")
(require "digitama/stdin.rkt")

(require "assignment.rkt")

(define ssh-connect : (-> String Natural
                          [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)]
                          [#:timeout (Option Nonnegative-Real)] [#:custodian Custodian] [#:payload-capacity Index]
                          [#:kexinit SSH-MSG-KEXINIT]
                          SSH-Port)
  (lambda [hostname port
                    #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]
                    #:timeout [timeout #false] #:custodian [root (make-custodian)] #:payload-capacity [payload-capacity 32768]
                    #:kexinit [kexinit (create-ssh:msg:kexinit)]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian])
      (define server-name : String (format "~a:~a" hostname port))
      (ssh-log-message 'debug "connecting to ~a:~a" hostname port)
      
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials 1 server-name server-name))
      (define sshc : Thread (sshc-ghostcat /dev/pout hostname port protoversion softwareversion comments payload-capacity))

      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
        (define server-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-connect))
        (ssh-log-message 'debug "server identification string: ~a" (SSH-Identification-raw server-id))

        (ssh-log-kexinit kexinit "local")
        (thread-send sshc kexinit)

        (define server-key : SSH-MSG-KEXINIT (ssh-read-special /dev/pin timeout ssh:msg:kexinit? 'ssh-connect))
        (ssh-log-kexinit server-key "server")

        (displayln (ssh-read-special /dev/pin timeout ssh:msg:kexdh:init? 'ssh-connect))

        (SSH-Port sshc-custodian sshc /dev/pin server-name)))))

(define ssh-listen : (->* (Natural)
                          (Index #:custodian Custodian #:hostname (Option String)
                                 #:protocol Positive-Flonum #:version (Option String) #:comments (Option String)
                                 #:kexinit SSH-MSG-KEXINIT)
                          SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:hostname [hostname #false]
                #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]
                #:kexinit [kexinit (create-ssh:msg:kexinit)]]
    (define listener-custodian : Custodian (make-custodian root))
    (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
    (define-values (id idsize) (ssh-identification-string protoversion (or softwareversion "") comments))
    (define-values (local-name local-port remote-name remote-port) (tcp-addresses sshd #true))
    (ssh-log-message 'debug "listening on ~a:~a" local-name local-port)
    (SSH-Listener listener-custodian sshd (substring id 0 idsize) kexinit
                  (format "~a:~a" local-name local-port) local-port)))

(define ssh-accept : (-> SSH-Listener [#:timeout (Option Nonnegative-Real)] [#:custodian Custodian] [#:payload-capacity Index] [#:kexinit SSH-MSG-KEXINIT] SSH-Port)
  (lambda [listener #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]
                    #:timeout [timeout #false] #:custodian [root (make-custodian)] #:payload-capacity [payload-capacity 32768]
                    #:kexinit [kexinit (SSH-Listener-kexinit listener)]]
    (define sshd-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshd-custodian])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break (SSH-Listener-watchdog listener)))
      (define-values (local-name local-port remote-name remote-port) (tcp-addresses /dev/tcpin #true))
      (ssh-log-message 'debug "accepted ~a:~a" remote-name remote-port)

      (define client-name : String (format "~a:~a" remote-name remote-port))
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials 1 client-name client-name))
      (define sshd : Thread (sshd-ghostcat /dev/pout (SSH-Listener-identification listener) /dev/tcpin /dev/tcpout payload-capacity))

      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
        (define client-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-accept))
        (ssh-log-message 'debug "client identification string: ~a" (SSH-Identification-raw client-id))
        
        (unless (= (SSH-Identification-protoversion client-id) protoversion)
          (thread-send sshd (create-ssh:msg:disconnect #:reason 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED))
          (thread-wait sshd)
          (throw exn:ssh:identification /dev/tcpin 'ssh-accept
                 "incompatible protoversion: ~a" (SSH-Identification-protoversion client-id)))

        (ssh-log-kexinit kexinit "local")
        (thread-send sshd kexinit)
        
        (define client-key : SSH-MSG-KEXINIT (ssh-read-special /dev/pin timeout ssh:msg:kexinit? 'ssh-accept))
        (ssh-log-kexinit client-key "client")

        (displayln (ssh-read-special /dev/pin timeout ssh:msg:kexdh:init? 'ssh-connect))
        
        (SSH-Port sshd-custodian sshd /dev/tcpin client-name)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-port-wait : (-> SSH-Port Void)
  (lambda [self]
    (thread-wait (SSH-Port-ghostcat self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-shutdown : (-> (U SSH-Port SSH-Listener) Void)
  (lambda [self]
    (cond [(SSH-Listener? self) (custodian-shutdown-all (SSH-Listener-custodian self))]
          [else (custodian-shutdown-all (SSH-Port-custodian self))])))
