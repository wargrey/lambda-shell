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

(define ssh-kex/starts-with-peer : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port Symbol SSH-Configuration String String Boolean Thread)
  (lambda [peer-kexinit self-kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))
    (define traffic : Nonnegative-Fixnum (ssh-write-message /dev/tcpout self-kexinit peer-name rfc))
    (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (thread-send parent e))])
                    (ssh-kex parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs traffic))))))

(define ssh-kex/starts-with-self : (-> SSH-MSG-KEXINIT Input-Port Output-Port Symbol SSH-Configuration String String Boolean Thread)
  (lambda [self-kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))
    (define sent : Nonnegative-Fixnum (ssh-write-message /dev/tcpout self-kexinit peer-name rfc))
    (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (thread-send parent e))])
                    (define-values (msg traffic) (ssh-read-transport-message /dev/tcpin peer-name rfc null))
                    (cond [(ssh:msg:kexinit? msg) (ssh-kex parent self-kexinit msg /dev/tcpin /dev/tcpout peer-name rfc Vc Vs (+ sent traffic))]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex/server : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port Symbol SSH-Configuration String String Natural Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs traffic]
    (ssh-log-kexinit self-kexinit "local server")
    (ssh-log-kexinit peer-kexinit "peer client")
    
    (let-values ([(kex hostkey c2s s2c) (ssh-negotiate peer-kexinit self-kexinit peer-name)])
      (ssh-kex parent kex hostkey c2s s2c /dev/tcpin /dev/tcpout peer-name rfc Vc Vs peer-kexinit self-kexinit traffic))))


(define ssh-kex/client : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port Symbol SSH-Configuration String String Natural Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout peer-name rfc Vc Vs traffic]
    (ssh-log-kexinit self-kexinit "local client")
    (ssh-log-kexinit peer-kexinit "peer server")

    (let-values ([(kex hostkey c2s s2c) (ssh-negotiate self-kexinit peer-kexinit peer-name)])
      (ssh-kex parent kex hostkey c2s s2c /dev/tcpin /dev/tcpout peer-name rfc Vc Vs self-kexinit peer-kexinit traffic))))

(define ssh-kex : (-> Thread (Pairof Symbol SSH-Kex) (Pairof Symbol SSH-HostKey) SSH-Package-Algorithms SSH-Package-Algorithms
                      Input-Port Output-Port Symbol SSH-Configuration String String SSH-MSG-KEXINIT SSH-MSG-KEXINIT Natural Void)
  (lambda [parent kex hostkey c2s s2c /dev/tcpin /dev/tcpout peer-name rfc Vc Vs Mc Ms traffic]
    (define kex-msg-group : (Listof Symbol) (list (vector-ref (cdr kex) 0)))
    (define exchange : (-> SSH-Message String String Bytes Bytes String (Option SSH-Message)) (vector-ref (cdr kex) 1))
    (define Ic : Bytes (ssh:msg:kexinit->bytes Mc))
    (define Is : Bytes (ssh:msg:kexinit->bytes Ms))
    (define Ks : String "")

    (let rekex ([traffic : Natural traffic])
      (define-values (msg traffic++) (ssh-read-transport-message /dev/tcpin peer-name rfc kex-msg-group))
      (cond [(and (ssh-message? msg) (ssh-key-exchange-message? msg) (exchange msg Vc Vs Ic Is Ks))
             => (λ [[m : SSH-Message]] (ssh-write-message /dev/tcpout m peer-name rfc))]
            [else (let ([undefined (make-ssh:msg:unimplemented #:number (if (bytes? msg) (bytes-ref msg 0) (ssh-message-number msg)))])
                    (ssh-write-message /dev/tcpout undefined peer-name rfc))])
      (rekex (+ traffic traffic++)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-negotiate : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT Symbol
                              (Values (Pairof Symbol SSH-Kex) (Pairof Symbol SSH-HostKey) SSH-Package-Algorithms SSH-Package-Algorithms))
  (lambda [ckexinit skexinit peer-name]
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

    (cond [(and kex hostkey c2s-cipher c2s-hmac c2s-compression s2c-cipher s2c-hmac s2c-compression)
           (ssh-log-message 'debug "kex: algorithm: ~a" (car kex))
           (ssh-log-message 'debug "kex: public key format: ~a" (car hostkey))
           (ssh-log-message 'debug "kex: server to client cipher: ~a MAC: ~a Compression: ~a" (car s2c-cipher) (car s2c-hmac) (car s2c-compression))
           (ssh-log-message 'debug "kex: client to server cipher: ~a MAC: ~a Compression: ~a" (car c2s-cipher) (car c2s-hmac) (car c2s-compression))
           (values kex hostkey (ssh-package-algorithms c2s-cipher c2s-hmac c2s-compression) (ssh-package-algorithms s2c-cipher s2c-hmac s2c-compression))]
          [(not c2s-compression) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching client to server compression algorithm")]
          [(not s2c-compression) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching server to client compression algorithm")]
          [(not c2s-hmac) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching client to server MAC algorithm")]
          [(not s2c-hmac) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching server to client MAC algorithm")]
          [(not c2s-cipher) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching client to server cipher")]
          [(not s2c-cipher) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching server to client cipher")]
          [(not hostkey) (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching public key format")]
          [else (throw exn:ssh:kex ssh-negotiate peer-name "kex: no matching algorihtm")])))

(define ssh-choose-algorithm : (All (a) (-> (SSH-Algorithm-Listof a) (SSH-Algorithm-Listof a) String (Option (Pairof Symbol a))))
  (lambda [cs-dirty ss-dirty type]
    (define cs : (SSH-Algorithm-Listof* a) (ssh-algorithms-clean cs-dirty))
    (define ss : (Listof Symbol) (ssh-algorithms->names ss-dirty))
    (findf (λ [[c : (Pairof Symbol a)]] (and (memv (car c) ss) #true)) cs)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-deal-with-generic-message : (-> SSH-Message Void)
  (lambda [msg]
    #;(cond [(bytes? msg) (write-special msg /dev/sshout)]
          [(ssh:msg:kexinit? msg) (ssh-kex/starts-with-peer msg kexinit /dev/tcpin /dev/tcpout rfc server?)]
          [(ssh:msg:disconnect? msg) (write-special eof /dev/sshout)]
          [(ssh-message-undefined? msg) (thread-send (current-thread) (make-ssh:msg:unimplemented #:number (ssh-message-number msg)))]
          [(not (ssh-ignored-incoming-message? msg)) (write-special msg /dev/sshout)])
    (void)))
