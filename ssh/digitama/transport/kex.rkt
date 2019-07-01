#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-7.1

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "message.rkt")
(require "newkeys.rkt")

(require "../kex.rkt")
(require "../assignment.rkt")
(require "../diagnostics.rkt")

(require "../../datatype.rkt")
(require "../../message.rkt")
(require "../../configuration.rkt")

(define-type SSH-Transport-Algorithms (Immutable-Vector SSH-Compression# SSH-Cipher# SSH-MAC#))

(define current-client-identification : (Parameterof String) (make-parameter ""))
(define current-server-identification : (Parameterof String) (make-parameter ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex/starts-with-peer : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Maybe-Newkeys Bytes Boolean Thread)
  (lambda [peer-kexinit self-kexinit /dev/tcpin /dev/tcpout rfc oldkeys Ic/s server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))

    (ssh-write-message /dev/tcpout self-kexinit rfc oldkeys)
    (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (thread-send parent e))])
                    (ssh-kex parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc oldkeys Ic/s))))))

(define ssh-kex/starts-with-self : (-> SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Maybe-Newkeys Boolean Thread)
  (lambda [self-kexinit /dev/tcpin /dev/tcpout rfc oldkeys server?]
    (define parent : Thread (current-thread))
    (define ssh-kex (if server? ssh-kex/server ssh-kex/client))

    (ssh-write-message /dev/tcpout self-kexinit rfc oldkeys)
    (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (thread-send parent e))])
                    (let rekex : Void ()
                      (define-values (msg payload _) (ssh-read-transport-message /dev/tcpin rfc oldkeys null))
                      (cond [(ssh:msg:kexinit? msg) (ssh-kex parent self-kexinit msg /dev/tcpin /dev/tcpout rfc oldkeys payload)]
                            [else (ssh-deal-with-unexpected-message (or msg payload) ssh-kex/starts-with-self)])))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex/server : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Maybe-Newkeys Bytes Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc oldkeys Ic]
    (ssh-log-kexinit self-kexinit "local server")
    (ssh-log-kexinit peer-kexinit "peer client")
    
    (define-values (kex hostkey c2s s2c) (ssh-negotiate peer-kexinit self-kexinit))
    (define HASH : (-> Bytes Bytes) (vector-ref kex 1))
    (define minbits : Positive-Index ($ssh-minimum-key-bits rfc))
    
    (define kex-self : SSH-Kex
      ((vector-ref kex 0) (current-client-identification) (current-server-identification) Ic (ssh:msg:kexinit->bytes self-kexinit)
                          ((vector-ref hostkey 0) (vector-ref hostkey 1) minbits) HASH minbits))

    (let ([kex-msg-group (list (ssh-kex-name kex-self))]
          [kex-reply (ssh-kex-reply kex-self)])
      (let rekex : Void ([secrets : (Option (Pairof Integer Bytes)) #false])
        (define-values (msg payload _) (ssh-read-transport-message /dev/tcpin rfc oldkeys kex-msg-group))
        (cond [(and (ssh-key-exchange-message? msg) (kex-reply kex-self msg))
               => (λ [[reply : (U SSH-Message (Pairof SSH-Message (Pairof Integer Bytes)))]]
                    (let-values ([(response K+H) (if (pair? reply) (values (car reply) (cdr reply)) (values reply secrets))])
                      (ssh-write-message /dev/tcpout response rfc oldkeys)
                      (rekex K+H)))]
              [(and (pair? secrets) (ssh:msg:newkeys? msg))
               (ssh-write-message /dev/tcpout msg rfc oldkeys)
               (ssh-kex-done parent oldkeys (car secrets) (cdr secrets) HASH c2s s2c /dev/tcpout rfc #true)]
              [else (ssh-deal-with-unexpected-message (or msg payload) ssh-kex/server)])))))

(define ssh-kex/client : (-> Thread SSH-MSG-KEXINIT SSH-MSG-KEXINIT Input-Port Output-Port SSH-Configuration Maybe-Newkeys Bytes Void)
  (lambda [parent self-kexinit peer-kexinit /dev/tcpin /dev/tcpout rfc oldkeys Is]
    (ssh-log-kexinit self-kexinit "local client")
    (ssh-log-kexinit peer-kexinit "peer server")

    (define-values (kex hostkey c2s s2c) (ssh-negotiate self-kexinit peer-kexinit))
    (define HASH : (-> Bytes Bytes) (vector-ref kex 1))
    (define minbits : Positive-Index ($ssh-minimum-key-bits rfc))
    
    (define kex-self : SSH-Kex
      ((vector-ref kex 0) (current-client-identification) (current-server-identification) (ssh:msg:kexinit->bytes self-kexinit) Is
                          ((vector-ref hostkey 0) (vector-ref hostkey 1) minbits) HASH minbits))

    (let ([kex-msg-group (list (ssh-kex-name kex-self))]
          [kex-verify (ssh-kex-verify kex-self)]
          [newkeys (make-ssh:msg:newkeys)])
      (ssh-write-message /dev/tcpout ((ssh-kex-request kex-self) kex-self) rfc oldkeys)
      (let rekex : Void ()
        (define-values (msg payload _) (ssh-read-transport-message /dev/tcpin rfc oldkeys kex-msg-group))
        (cond [(and (ssh-key-exchange-message? msg) (kex-verify kex-self msg))
               => (λ [[result : (U SSH-Message (Pairof Integer Bytes))]]
                    (let-values ([(response secrets) (if (pair? result) (values newkeys result) (values result #false))])
                      (ssh-write-message /dev/tcpout response rfc oldkeys)
                      (cond [(not secrets) (rekex)]
                            [else (ssh-kex-done parent oldkeys (car secrets) (cdr secrets) HASH c2s s2c /dev/tcpout rfc #false)])))]
              [else (ssh-deal-with-unexpected-message (or msg payload) ssh-kex/client)])))))
  
(define ssh-kex-done : (-> Thread Maybe-Newkeys Integer Bytes (-> Bytes Bytes)
                           SSH-Transport-Algorithms SSH-Transport-Algorithms Output-Port SSH-Configuration Boolean Void)
  (lambda [parent maybe-oldkeys shared-secret H HASH c2s s2c /dev/tcpout rfc server?]
    (define K : Bytes (ssh-mpint->bytes shared-secret))
    (define-values (session-id parcel)
      (cond [(ssh-parcel? maybe-oldkeys) (values H maybe-oldkeys)]
            [else (values (ssh-newkeys-identity maybe-oldkeys)
                          (ssh-newkeys-parcel maybe-oldkeys))]))
    
    (define-values (c2s-compression s2c-compression) (values (vector-ref c2s 0) (vector-ref s2c 0)))
    (define-values (c2s-cipher s2c-cipher) (values (vector-ref c2s 1) (vector-ref s2c 1)))
    (define-values (c2s-cipher-block-size-in-bytes s2c-cipher-block-size-in-bytes) (values (vector-ref c2s-cipher 1) (vector-ref s2c-cipher 1)))
    (define-values (c2s-cipher-key-size-in-bytes s2c-cipher-key-size-in-bytes) (values (vector-ref c2s-cipher 2) (vector-ref s2c-cipher 2)))
    (define-values (c2s-hmac s2c-hmac) (values (vector-ref c2s 2) (vector-ref s2c 2)))
    (define-values (c2s-hmac-key-size-in-bytes s2c-hmac-key-size-in-bytes) (values (vector-ref c2s-hmac 1) (vector-ref s2c-hmac 1)))
    
    (define c2s-initialization-vector : Bytes (ssh-derive-key K H #\A session-id c2s-cipher-block-size-in-bytes HASH))
    (define s2c-initialization-vector : Bytes (ssh-derive-key K H #\B session-id s2c-cipher-block-size-in-bytes HASH))
    (define c2s-cipher-key : Bytes (ssh-derive-key K H #\C session-id c2s-cipher-key-size-in-bytes HASH))
    (define s2c-cipher-key : Bytes (ssh-derive-key K H #\D session-id s2c-cipher-key-size-in-bytes HASH))
    (define c2s-mac-key : Bytes (ssh-derive-key K H #\E session-id c2s-hmac-key-size-in-bytes HASH))
    (define s2c-mac-key : Bytes (ssh-derive-key K H #\F session-id s2c-hmac-key-size-in-bytes HASH))

    (define-values (c2s-inflate c2s-deflate) (values (vector-ref c2s-compression 0) (vector-ref c2s-compression 1)))
    (define-values (s2c-inflate s2c-deflate) (values (vector-ref s2c-compression 0) (vector-ref s2c-compression 1)))
    (define-values (c2s-encrypt c2s-decrypt) ((vector-ref c2s-cipher 0) c2s-initialization-vector c2s-cipher-key))
    (define-values (s2c-encrypt s2c-decrypt) ((vector-ref s2c-cipher 0) s2c-initialization-vector s2c-cipher-key))
    (define-values (c2s-digest s2c-digest) (values ((vector-ref c2s-hmac 0) c2s-mac-key) ((vector-ref s2c-hmac 0) s2c-mac-key)))

    (define newkeys : SSH-Newkeys
      (if (and server?)
          (ssh-newkeys session-id parcel
                       s2c-inflate c2s-deflate
                       s2c-encrypt c2s-decrypt s2c-cipher-block-size-in-bytes c2s-cipher-block-size-in-bytes
                       s2c-digest c2s-digest)
          (ssh-newkeys session-id parcel
                       c2s-inflate s2c-deflate
                       c2s-encrypt s2c-decrypt c2s-cipher-block-size-in-bytes s2c-cipher-block-size-in-bytes
                       c2s-digest s2c-digest)))
    
    (ssh-parcel-action-on-rekexed parcel)

    (let send-in-flight-messages ([traffic : Natural 0])
      (define maybe-message (thread-try-receive))
      (cond [(ssh-message? maybe-message) (send-in-flight-messages (ssh-write-message /dev/tcpout maybe-message rfc newkeys))]
            [else (thread-send parent (cons newkeys traffic))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-negotiate : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT (Values SSH-Kex# SSH-Hostkey# SSH-Transport-Algorithms SSH-Transport-Algorithms))
  (lambda [Mc Ms]
    (define-values (kex hostkey)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-kexes Mc) (ssh:msg:kexinit-kexes Ms) "algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-hostkeys Mc) (ssh:msg:kexinit-hostkeys Ms) "host key format")))

    (define-values (c2s-cipher s2c-cipher)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-ciphers Mc) (ssh:msg:kexinit-c2s-ciphers Ms) "client to server cipher")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-ciphers Mc) (ssh:msg:kexinit-s2c-ciphers Ms) "server to client cipher")))
    
    (define-values (c2s-mac s2c-mac)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-macs Mc) (ssh:msg:kexinit-c2s-macs Ms) "client to server MAC algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-macs Mc) (ssh:msg:kexinit-s2c-macs Ms) "server to client MAC algorithm")))
      
    (define-values (c2s-compression s2c-compression)
      (values (ssh-choose-algorithm (ssh:msg:kexinit-c2s-compressions Mc) (ssh:msg:kexinit-c2s-compressions Ms) "client to server compression algorithm")
              (ssh-choose-algorithm (ssh:msg:kexinit-s2c-compressions Mc) (ssh:msg:kexinit-s2c-compressions Ms) "server to client compression algorithm")))

    (cond [(and kex hostkey c2s-cipher c2s-mac c2s-compression s2c-cipher s2c-mac s2c-compression)
           (ssh-log-message 'debug "kex: algorithm: ~a" (car kex))
           (ssh-log-message 'debug "kex: public key format: ~a" (car hostkey))
           (ssh-log-message 'debug "kex: server to client cipher: ~a MAC: ~a Compression: ~a" (car s2c-cipher) (car s2c-mac) (car s2c-compression))
           (ssh-log-message 'debug "kex: client to server cipher: ~a MAC: ~a Compression: ~a" (car c2s-cipher) (car c2s-mac) (car c2s-compression))
           (values (cdr kex) (cdr hostkey)
                   (vector-immutable (cdr c2s-compression) (cdr c2s-cipher) (cdr c2s-mac))
                   (vector-immutable (cdr s2c-compression) (cdr s2c-cipher) (cdr s2c-mac)))]
          [(not c2s-compression) (ssh-raise-kex-error ssh-negotiate "kex: no matching client to server compression algorithm")]
          [(not s2c-compression) (ssh-raise-kex-error ssh-negotiate "kex: no matching server to client compression algorithm")]
          [(not c2s-mac) (ssh-raise-kex-error ssh-negotiate "kex: no matching client to server MAC algorithm")]
          [(not s2c-mac) (ssh-raise-kex-error ssh-negotiate "kex: no matching server to client MAC algorithm")]
          [(not c2s-cipher) (ssh-raise-kex-error ssh-negotiate "kex: no matching client to server cipher")]
          [(not s2c-cipher) (ssh-raise-kex-error ssh-negotiate "kex: no matching server to client cipher")]
          [(not hostkey) (ssh-raise-kex-error ssh-negotiate "kex: no matching public key format")]
          [else (ssh-raise-kex-error ssh-negotiate "kex: no matching algorihtm")])))

(define ssh-choose-algorithm : (All (a) (-> (SSH-Algorithm-Listof a) (SSH-Algorithm-Listof a) String (Option (Pairof Symbol a))))
  (lambda [cs-dirty ss-dirty type]
    (define cs : (SSH-Algorithm-Listof* a) (ssh-algorithms-clean cs-dirty))
    (define ss : (Listof Symbol) (ssh-algorithms->names ss-dirty))
    
    (findf (λ [[c : (Pairof Symbol a)]] (and (memv (car c) ss) #true)) cs)))

(define ssh-derive-key : (-> Bytes Bytes Char Bytes Index (-> Bytes Bytes) Bytes)
  (lambda [K H salt session-id key-size HASH]
    (define K1 : Bytes (HASH (bytes-append K H (bytes (char->integer salt)) session-id)))

    (let Σ : Bytes ([ΣK : Bytes K1])
      (define size : Index (bytes-length ΣK))
      (cond [(< size key-size) (Σ (bytes-append ΣK (HASH (bytes-append K H ΣK))))]
            [(= size key-size) ΣK]
            [else (subbytes ΣK 0 key-size)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-deal-with-unexpected-message : (-> (U SSH-Message Bytes) Any Void)
  (lambda [msg func]
    (ssh-raise-kex-error func "kex: unexpected message: ~a" (if (bytes? msg) (bytes-ref msg 0) (ssh-message-name msg)))))
