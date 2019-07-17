#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require digimon/binscii)

(require "../userauth.rkt")
(require "../message.rkt")
(require "../diagnostics.rkt")

(require "../fsio/pem.rkt")
(require "../fsio/rsa.rkt")
(require "../fsio/authorized-keys.rkt")

(require "../algorithm/fingerprint.rkt")
(require "../algorithm/hostkey/rsa.rkt")

(require "../message/transport.rkt")
(require "../message/authentication.rkt")

(require "../../datatype.rkt")

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require (for-syntax "../message/authentication.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; https://tools.ietf.org/html/rfc4252#section-8
(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST
  [PUBLICKEY #:method 'publickey ([signed? : Boolean #false] [algorithm : Symbol] [key : Bytes]) #:case signed?])

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST-PUBLICKEY
  [($)       #:signed? '#true ([signature : Bytes #""])])

(define-ssh-shared-messages publickey
  [SSH_MSG_USERAUTH_PK_OK 60 ([algorithm : Symbol] [key : Bytes])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Userauth-Private-Key (List Symbol Bytes Path Any))

(struct ssh-publickey-userauth ssh-userauth
  ([keys : (Option (Listof SSH-Userauth-Private-Key))])
  #:type-name SSH-Publickey-Userauth)

(define make-ssh-publickey-userauth : SSH-Userauth-Constructor
  (lambda [name server?]
    (ssh-publickey-userauth (super-ssh-userauth #:name name
                                                #:request ssh-publickey-request
                                                #:response ssh-publickey-response)
                            #false)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-publickey-request : SSH-Userauth-Request
  (lambda [self username service response session]
    (with-asserts ([self ssh-publickey-userauth?])
      (define publickey-okay? (or (eq? response #true) (ssh:msg:userauth:pk:ok? response)))
      (define prev-keys : (Option (Listof SSH-Userauth-Private-Key)) (ssh-publickey-userauth-keys self))
      (define rest-keys : (Listof SSH-Userauth-Private-Key)
        (cond [(and publickey-okay?) (or prev-keys null)]
              [(pair? prev-keys) (cdr prev-keys)]
              [(null? prev-keys) null]
              [else (ssh-filter-keys (read-directory-private-keys))]))

      (cond [(null? rest-keys) (values self #false)]
            [else (values (if (eq? prev-keys rest-keys) self (struct-copy ssh-publickey-userauth self [keys rest-keys]))
                          (let-values ([(type pubkey src) (values (caar rest-keys) (cadar rest-keys) (caddar rest-keys))])
                            (if (not publickey-okay?)
                                (and (ssh-log-message 'debug "try public key: ~a ~a" src (ssh-fingerprint type pubkey))
                                     (make-ssh:msg:userauth:request:publickey #:username username #:service service #:algorithm type #:key pubkey))
                                (let* ([key (cadddr (car rest-keys))]
                                       [pre-request (make-ssh:msg:userauth:request:publickey$ #:username username #:service service #:algorithm type #:key pubkey)]
                                       [message (ssh-signature-message session pre-request)])
                                  (define signature : Bytes
                                    (cond [(rsa-private-key? key) (rsa-make-signature key message)]
                                          [else #| dead code |# #""]))
                                  (define-values (sign-algname sigoff) (ssh-bytes->name signature))
                                  (ssh-log-message 'debug "~a is accepted, use '~a' to sign and send public key: ~a" src sign-algname (ssh-fingerprint type pubkey))
                                  (struct-copy ssh:msg:userauth:request:publickey$ pre-request
                                               [signature signature])))))]))))

(define ssh-publickey-response : SSH-Userauth-Response
  (lambda [self request username service session]
    (with-handlers ([exn:fail:filesystem? (λ _ (make-ssh:msg:disconnect #:reason 'SSH-DISCONNECT-ILLEGAL-USER-NAME))])
      (define authorized-keys : (Option (Immutable-HashTable Symbol (Listof SSH-Authorized-Key)))
        (let ([.authorized-keys (build-path (expand-user-path (format "~~~a/.ssh/authorized_keys" username)))])
          (and (file-exists? .authorized-keys)
               (read-authorized-keys* .authorized-keys))))
      
      (and authorized-keys
           (ssh:msg:userauth:request:publickey? request)
           (let* ([keytype (ssh:msg:userauth:request:publickey-algorithm request)]
                  [rawkey (ssh:msg:userauth:request:publickey-key request)]
                  [athkey (authorized-key-ref authorized-keys keytype rawkey)])
             (and (ssh-authorized-key? athkey)
                  (if (not (ssh:msg:userauth:request:publickey$? request))
                      (and (ssh-log-message 'debug "accepted ~a, continue to verify" (ssh-fingerprint keytype rawkey))
                           (make-ssh:msg:userauth:pk:ok #:algorithm keytype #:key rawkey))
                      (let*-values ([(message) (ssh-signature-message session request)]
                                    [(signature) (ssh:msg:userauth:request:publickey$-signature request)]
                                    [(sigalg-name sigoff) (rsa-bytes-signature-info signature)])
                        (and (case sigalg-name
                               [(ssh-rsa rsa-sha2-256)
                                (let-values ([(pubkey) (rsa-bytes->public-key (ssh-authorized-key-raw athkey))])
                                  (and (eq? keytype ssh-rsa-keyname)
                                       (ssh-rsa-verify pubkey message signature sigoff sigalg-name)
                                       (ssh-log-message 'debug "verified ~a, signed with '~a'" (ssh-fingerprint keytype rawkey) sigalg-name)))]
                               [else #false])
                             (or (ssh-authorized-key-options athkey) #true))))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-signature-message : (-> Bytes SSH-MSG-USERAUTH-REQUEST-PUBLICKEY Bytes)
  (lambda [session message]
    (bytes-append (ssh-bstring->bytes session) (ssh:msg:userauth:request:publickey->bytes message))))

(define ssh-fingerprint : (-> Symbol Bytes String)
  (lambda [type key]
    (ssh-key-fingerprint type key #:hash sha256-bytes #:digest base64-encode)))

(define ssh-filter-keys : (-> (Listof PEM-Key) (Listof SSH-Userauth-Private-Key))
  (lambda [private-keys]
    (let select-keys ([all-keys : (Listof PEM-Key) (read-directory-private-keys)]
                      [syek : (Listof SSH-Userauth-Private-Key) null])
      (cond [(null? all-keys) (reverse syek)]
            [else (case (pem-key-type (car all-keys))
                    [(|RSA PRIVATE KEY|)
                     (define key : RSA-Private-Key (unsafe-bytes->rsa-private-key* (pem-key-raw (car all-keys))))
                     (select-keys (cdr all-keys)
                                  (cons (list ssh-rsa-keyname (rsa-make-public-key key) (pem-key-src (car all-keys)) key) syek))]
                    [else (select-keys (cdr all-keys) syek)])]))))
