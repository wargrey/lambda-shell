#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-7.1

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "message.rkt")
(require "newkeys.rkt")

(require "../kex.rkt")
(require "../message.rkt")
(require "../assignment.rkt")
(require "../diagnostics.rkt")

(require "../assignment/message.rkt")
(require "../message/transport.rkt")
(require "../message/disconnection.rkt")

(require "../../datatype.rkt")
(require "../../configuration.rkt")

(define-type SSH-Transport-Algorithms (Immutable-Vector SSH-Compression# SSH-Cipher# SSH-MAC#))
(define-type SSH-Kex-Process (-> SSH-Kex SSH-Message (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-kex/server : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT SSH-Configuration Maybe-Newkeys String String Bytes (U (Pairof SSH-Kex SSH-Kex-Process) SSH-Message))
  (lambda [self-kexinit peer-kexinit rfc oldkeys Vc Vs Ic]
    (ssh-log-kexinit self-kexinit "local server" 'debug)
    (ssh-log-kexinit peer-kexinit "peer client" 'debug)

    (let ([algorithms (ssh-negotiate peer-kexinit self-kexinit)])
      (if (string? algorithms)
          (make-ssh:disconnect:key:exchange:failed #:source ssh-negotiate algorithms)

          (let-values ([(kex hostkey c2s s2c) (values (car algorithms) (cadr algorithms) (caddr algorithms) (cadddr algorithms))])
            (define HASH : (-> Bytes Bytes) (vector-ref kex 1))
            (define minbits : Positive-Index ($ssh-minimum-key-bits rfc))
            (define &secrets : (Boxof (Option (Pairof Integer Bytes))) (box #false))
            
            ((inst cons SSH-Kex SSH-Kex-Process)
             ((vector-ref kex 0) Vc Vs Ic (ssh:msg:kexinit->bytes self-kexinit) ((vector-ref hostkey 0) (vector-ref hostkey 1) minbits) HASH minbits)
             
             (λ [[kex-self : SSH-Kex] [msg : SSH-Message]] : (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys)
               (or (and (ssh-kex-message? msg)
                        (let-values ([(kex-self reply) (ssh-kex.reply kex-self msg)])
                          (and reply
                               (cond [(ssh-message? reply) (cons kex-self reply)]
                                     [else (set-box! &secrets (cdr reply)) (cons kex-self (car reply))]))))
                   (and (ssh:msg:newkeys? msg)
                        (let ([secrets (unbox &secrets)])
                          (and (pair? secrets)
                               (ssh-kex-done oldkeys (car secrets) (cdr secrets) HASH c2s s2c rfc #true))))
                   (cons kex-self (ssh-deal-with-unexpected-message msg ssh-kex/server))))))))))

(define ssh-kex/client : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT SSH-Configuration Maybe-Newkeys String String Bytes
                             (Pairof (Option (Pairof SSH-Kex SSH-Kex-Process)) SSH-Message))
  (lambda [self-kexinit peer-kexinit rfc oldkeys Vc Vs Is]
    (ssh-log-kexinit self-kexinit "local client" 'debug)
    (ssh-log-kexinit peer-kexinit "peer server" 'debug)

    (let ([algorithms (ssh-negotiate peer-kexinit self-kexinit)])
      (if (string? algorithms)
          (cons #false (make-ssh:disconnect:key:exchange:failed #:source ssh-negotiate algorithms))

          (let-values ([(kex hostkey c2s s2c) (values (car algorithms) (cadr algorithms) (caddr algorithms) (cadddr algorithms))])
            (define HASH : (-> Bytes Bytes) (vector-ref kex 1))
            (define minbits : Positive-Index ($ssh-minimum-key-bits rfc))
            (define &secrets : (Boxof (Option (Pairof Integer Bytes))) (box #false))

            (define-values (kex-self req)
              (ssh-kex.request ((vector-ref kex 0) Vc Vs (ssh:msg:kexinit->bytes self-kexinit) Is
                                                   ((vector-ref hostkey 0) (vector-ref hostkey 1) minbits) HASH minbits)))
    
            (cons (cons kex-self
                        (λ [[kex-self : SSH-Kex] [msg : SSH-Message]] : (U (Pairof SSH-Kex SSH-Message) SSH-Newkeys)
                          (or (and (ssh-kex-message? msg)
                                   (let-values ([(kex-self result) (ssh-kex.verify kex-self msg)])
                                     (and result
                                          (cond [(not (pair? result)) (cons kex-self result)]
                                                [else (set-box! &secrets result) (cons kex-self SSH:NEWKEYS)]))))
                              (and (ssh:msg:newkeys? msg)
                                   (let ([secrets (unbox &secrets)])
                                     (and (pair? secrets)
                                          (ssh-kex-done oldkeys (car secrets) (cdr secrets) HASH c2s s2c rfc #false))))
                              (cons kex-self (ssh-deal-with-unexpected-message msg ssh-kex/client)))))
                  req))))))
  
(define ssh-kex-done : (-> Maybe-Newkeys Integer Bytes (-> Bytes Bytes)
                           SSH-Transport-Algorithms SSH-Transport-Algorithms SSH-Configuration Boolean SSH-Newkeys)
  (lambda [maybe-oldkeys shared-secret H HASH c2s s2c rfc server?]
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
    newkeys))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-negotiate : (-> SSH-MSG-KEXINIT SSH-MSG-KEXINIT (U (List SSH-Kex# SSH-Hostkey# SSH-Transport-Algorithms SSH-Transport-Algorithms) String))
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

    (cond [(not c2s-compression) "kex: no matching client to server compression algorithm"]
          [(not s2c-compression) "kex: no matching server to client compression algorithm"]
          [(not c2s-mac) "kex: no matching client to server MAC algorithm"]
          [(not s2c-mac) "kex: no matching server to client MAC algorithm"]
          [(not c2s-cipher) "kex: no matching client to server cipher"]
          [(not s2c-cipher) "kex: no matching server to client cipher"]
          [(not hostkey) "kex: no matching public key format"]
          [(not kex) "kex: no matching algorihtm"]
          [else (let ([level 'info])
                  (ssh-log-message level "kex: algorithm: ~a" (car kex))
                  (ssh-log-message level "kex: public key format: ~a" (car hostkey))
                  (ssh-log-message level "kex: server to client cipher: ~a MAC: ~a Compression: ~a" (car s2c-cipher) (car s2c-mac) (car s2c-compression))
                  (ssh-log-message level "kex: client to server cipher: ~a MAC: ~a Compression: ~a" (car c2s-cipher) (car c2s-mac) (car c2s-compression))
                  (list (cdr kex) (cdr hostkey)
                        (vector-immutable (cdr c2s-compression) (cdr c2s-cipher) (cdr c2s-mac))
                        (vector-immutable (cdr s2c-compression) (cdr s2c-cipher) (cdr s2c-mac))))])))

(define ssh-choose-algorithm : (All (a) (-> (SSH-Name-Listof a) (SSH-Name-Listof a) String (Option (Pairof Symbol a))))
  (lambda [cs-dirty ss-dirty type]
    (define cs : (SSH-Name-Listof* a) (ssh-names-clean cs-dirty))
    (define ss : (Listof Symbol) (ssh-names->namelist ss-dirty))
    
    (findf (λ [[c : (Pairof Symbol a)]] (and (memv (car c) ss) #true)) cs)))

(define ssh-derive-key : (-> Bytes Bytes Char Bytes Index (-> Bytes Bytes) Bytes)
  (lambda [K H salt session-id key-size HASH]
    (define K1 : Bytes (HASH (bytes-append K H (bytes (char->integer salt)) session-id)))

    (let Σ : Bytes ([ΣK : Bytes K1])
      (define size : Index (bytes-length ΣK))
      (cond [(< size key-size) (Σ (bytes-append ΣK (HASH (bytes-append K H ΣK))))]
            [(= size key-size) ΣK]
            [else (subbytes ΣK 0 key-size)]))))

(define ssh-mac-capacity : (-> SSH-MSG-KEXINIT Index)
  (lambda [kexinit]
    (apply max
           (map (λ [[name : (Pairof Symbol SSH-MAC#)]]
                  (vector-ref (cdr name) 1))
                (ssh-names-clean (append (ssh:msg:kexinit-c2s-macs kexinit)
                                         (ssh:msg:kexinit-s2c-macs kexinit)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-deal-with-unexpected-message : (-> SSH-Message Procedure SSH-MSG-DISCONNECT)
  (lambda [msg func]
    (make-ssh:disconnect:key:exchange:failed #:source func "kex: unexpected message: ~a" (ssh-message-name msg))))
