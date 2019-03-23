#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-7.1

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "message.rkt")

(require "../../assignment.rkt")
(require "../assignment.rkt")

(require "../datatype.rkt")
(require "../configuration.rkt")
(require "../diagnostics.rkt")

(struct key
  ([secret : Bytes]
   [hash : Bytes]
   [traffic : Natural])
  #:transparent
  #:type-name Key)

(define ssh-kex/starts-with-peer : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Boolean Thread)
  (lambda [peer-kexinit self-kexinit /dev/tcpin /dev/tcpout rfc server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))
    (define traffic : Nonnegative-Fixnum (ssh-write-message /dev/tcpout self-kexinit rfc))
    (thread (λ [] (ssh-kex parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc traffic)))))

(define ssh-kex/starts-with-self : (-> SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Boolean Thread)
  (lambda [self-kexinit /dev/tcpin /dev/tcpout rfc server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))
    (define sent : Nonnegative-Fixnum (ssh-write-message /dev/tcpout self-kexinit rfc))
    (thread (λ [] (let-values ([(msg traffic) (ssh-read-transport-message /dev/tcpin rfc null)])
                    (cond [(ssh:msg:kexinit? msg) (ssh-kex parent self-kexinit msg /dev/tcpin /dev/tcpout rfc (+ sent traffic))]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex/server : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Natural Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc traffic]
    (ssh-log-kexinit self-kexinit "local server")
    (ssh-log-kexinit peer-kexinit "peer client")
    
    #;(ssh-negotiation peer-kexinit self-kexinit)

    (let kex ([traffic : Natural traffic])
      (define-values (msg traffic++) (ssh-read-transport-message /dev/tcpin rfc null))
      (cond [(ssh:msg:kexdh:init? msg) (displayln msg)])
      (kex (+ traffic traffic++)))))


(define ssh-kex/client : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Natural Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc traffic]
    (ssh-log-kexinit self-kexinit "local client")
    (ssh-log-kexinit peer-kexinit "peer server")

    #;(ssh-negotiation self-kexinit peer-kexinit)

    (let kex ([traffic : Natural traffic])
      (define-values (msg traffic++) (ssh-read-transport-message /dev/tcpin rfc null))
      #;(displayln msg)
      (kex (+ traffic traffic++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#;(define ssh-negotiation : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT (Values (Pairof Symbol SSH-Kex) (Pairof Symbol SSH-HostKey) SSH-Package-Algorithms SSH-Package-Algorithms))
  (lambda [ckexinit skexinit]
    (define-values (kex hostkey)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-kexes ckexinit) (ssh:msg:kexinit-kexes skexinit) "algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-hostkeys ckexinit) (ssh:msg:kexinit-hostkeys skexinit) "host key format")))

    (define-values (c2s-cipher s2c-cipher)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-ciphers ckexinit) (ssh:msg:kexinit-c2s-ciphers skexinit) "client to server cipher")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-ciphers ckexinit) (ssh:msg:kexinit-s2c-ciphers skexinit) "server to client cipher")))
    
    (define-values (c2s-hmac s2c-hmac)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-macs ckexinit) (ssh:msg:kexinit-c2s-macs skexinit) "client to server MAC algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-macs ckexinit) (ssh:msg:kexinit-s2c-macs skexinit) "server to client MAC algorithm")))
      
    (define-values (c2s-compression s2c-compression)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-compressions ckexinit) (ssh:msg:kexinit-c2s-compressions skexinit) "client to server compression algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-compressions ckexinit) (ssh:msg:kexinit-s2c-compressions skexinit) "server to client compression algorithm")))
    
    (values key hostkey
            (ssh-package-algorithms c2s-cipher c2s-hmac c2s-compression)
            (ssh-package-algorithms s2c-cipher s2c-hmac s2c-compression))))

(define ssh-choose-algorithm : (All (a) (-> (SSH-Algorithm-Listof a) (SSH-Algorithm-Listof a) String (Option (Pairof Symbol a))))
  (lambda [cs-dirty ss-dirty type]
    (define cs : (SSH-Algorithm-Listof* a) (ssh-algorithms-clean cs-dirty))
    (define ss : (Listof Symbol) (ssh-algorithms->names ss-dirty))
    (define algorithm : (Option (Pairof Symbol a)) (findf (λ [[c : (Pairof Symbol a)]] (and (memv (car c) ss) #true)) cs))

    (ssh-log-message 'debug "kex: ~a: ~a" type (if (not algorithm) "(no match)" (car algorithm)))
    
    algorithm))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-deal-with-generic-message : (-> SSH-Message Void)
  (lambda [msg]
    #;(cond [(bytes? msg) (write-special msg /dev/sshout)]
          [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout rfc server?)]
          [(ssh:msg:disconnect? msg) (write-special eof /dev/sshout)]
          [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
          [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)])
    (void)))
