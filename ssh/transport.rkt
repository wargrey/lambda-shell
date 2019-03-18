#lang typed/racket/base

(provide (all-defined-out))

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
                          SSH-Port)
  (lambda [hostname port
                    #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]
                    #:timeout [timeout #false] #:custodian [root (make-custodian)] #:payload-capacity [payload-capacity 32768]]
    (define sshc-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshc-custodian])
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials 1 hostname hostname))
      (define sshc : Thread (sshc-ghostcat /dev/pout hostname port protoversion softwareversion comments payload-capacity))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshc-custodian) (raise e))])
        (define server-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-connect))
        (displayln server-id)
        (thread-send sshc (create-ssh:msg:kexinit))
        (define server-key : SSH-Message (ssh-read-special /dev/pin timeout SSH-Message? 'ssh-connect))
        (displayln server-key)
        (SSH-Port sshc-custodian sshc /dev/pin)))))

(define ssh-listen : (->* (Natural)
                          (Index #:custodian Custodian #:hostname (Option String)
                                 #:protocol Positive-Flonum #:version (Option String) #:comments (Option String))
                          SSH-Listener)
  (lambda [port [max-allow-wait 4]
                #:custodian [root (make-custodian)] #:hostname [hostname #false]
                #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]]
    (define listener-custodian : Custodian (make-custodian root))
    (define sshd : TCP-Listener (tcp-listen port max-allow-wait #true hostname))
    (define-values (id idsize) (ssh-identification-string protoversion (or softwareversion "") comments))
    (SSH-Listener listener-custodian sshd (substring id 0 idsize))))

(define ssh-accept : (-> SSH-Listener [#:timeout (Option Nonnegative-Real)] [#:custodian Custodian] [#:payload-capacity Index] SSH-Port)
  (lambda [listener #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false]
                    #:timeout [timeout #false] #:custodian [root (make-custodian)] #:payload-capacity [payload-capacity 32768]]
    (define sshd-custodian : Custodian (make-custodian root))
    (parameterize ([current-custodian sshd-custodian])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break (SSH-Listener-watchdog listener)))
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials))
      (define sshd : Thread (sshd-ghostcat (SSH-Listener-identification listener) /dev/tcpin /dev/tcpout payload-capacity /dev/pout))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all sshd-custodian) (raise e))])
        (define peer-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-accept))
        (displayln peer-id)
        (when (= (SSH-Identification-protoversion peer-id) protoversion)
          (thread-send sshd (create-ssh:msg:disconnect #:reason 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED))
          (thread-wait sshd)
          (throw exn:ssh:identification /dev/tcpin 'ssh-accept
                 "incompatible protoversion: ~a" (SSH-Identification-protoversion peer-id)))
        (define peer-key : SSH-Message (ssh-read-special /dev/pin timeout SSH-Message? 'ssh-accept))
        (displayln peer-key)
        (SSH-Port sshd-custodian sshd /dev/tcpin)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-port-wait : (-> SSH-Port Void)
  (lambda [self]
    (thread-wait (SSH-Port-ghostcat self))))

(define ssh-port-shutdown : (-> (U SSH-Port SSH-Listener) Void)
  (lambda [self]
    (cond [(SSH-Listener? self) (custodian-shutdown-all (SSH-Listener-custodian self))]
          [else (custodian-shutdown-all (SSH-Port-custodian self))])))
