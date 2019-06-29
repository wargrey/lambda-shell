#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "../userauth.rkt")
(require "../fsio/authorized-keys.rkt")

(require "../algorithm/pkcs1/key.rkt")
(require "../algorithm/pkcs1/hash.rkt")
(require "../algorithm/pkcs1/emsa-v1_5.rkt")

(require "../message.rkt")
(require "../../message.rkt")
(require "../../datatype.rkt")

(require "../diagnostics.rkt")

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require (for-syntax "../../message.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; https://tools.ietf.org/html/rfc4252#section-8
(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST
  [PUBLICKEY #:method 'publickey ([signed? : Boolean #false] [algorithm : Symbol] [key : SSH-BString]) #:case signed?])

(define-ssh-case-messages SSH-MSG-USERAUTH-REQUEST-PUBLICKEY
  [($)       #:adequate? '#true ([signature : SSH-BString])])

(define-ssh-shared-messages publickey
  [SSH_MSG_USERAUTH_PK_OK 60 ([algorithm : Symbol] [key : SSH-BString])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-userauth-publickey% : SSH-User-Authentication<%>
  (class object% (super-new)
    (init-field session-id)

    (define/public (tell-method-name)
      'publickey)

    (define/public (request username service response)
      (or response (make-ssh:msg:userauth:request #:username username #:service service #:method 'publickey)))

    (define/public (response request username service)
      (with-handlers ([exn:fail:filesystem? (λ _ (make-ssh:msg:disconnect #:reason 'SSH-DISCONNECT-ILLEGAL-USER-NAME))])
        (define authorized-keys : (Option (Immutable-HashTable Symbol (Listof Authorized-Key)))
          (let ([.authorized-keys (build-path (expand-user-path (format "~~~a/.ssh/authorized_keys" username)))])
            (and (file-exists? .authorized-keys)
                 (read-authorized-keys* .authorized-keys))))

        (and authorized-keys
             (ssh:msg:userauth:request:publickey? request)
             (let* ([keytype (ssh:msg:userauth:request:publickey-algorithm request)]
                    [rawkey (ssh:msg:userauth:request:publickey-key request)]
                    [key (authorized-key-ref authorized-keys keytype rawkey)])
               (and (authorized-key? key)
                    (if (not (ssh:msg:userauth:request:publickey$? request))
                        (and (ssh-log-message 'debug "accepted ~a, continue for verifying" (authorized-key-fingerprint key))
                             (make-ssh:msg:userauth:pk:ok #:algorithm keytype #:key rawkey))
                        (let ([message (bytes-append (ssh-bstring->bytes session-id) (ssh:msg:userauth:request:publickey->bytes request))])
                          (and (case keytype
                                 [(ssh-rsa)
                                  (let ([pubkey (ssh-bytes->rsa-public-key (authorized-key-raw key))]
                                        [sigraw (ssh-bytes->rsa-signature (ssh:msg:userauth:request:publickey$-signature request))])
                                    (and (rsa-verify pubkey message sigraw id-sha1)
                                         (ssh-log-message 'debug "verified ~a" (authorized-key-fingerprint key))))]
                                 [else #false])
                               (or (authorized-key-options key) #true)))))))))

    (define/public (abort)
      (void))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-bytes->rsa-public-key : (-> Bytes RSA-Public-Key)
  (lambda [key]
    (let*-values ([(_ offset) (ssh-bytes->string key)]
                  [(e offset) (ssh-bytes->mpint key offset)]
                  [(n offset) (ssh-bytes->mpint key offset)])
      (make-rsa-public-key #:e e #:n n))))

(define ssh-bytes->rsa-signature : (-> Bytes Bytes)
  (lambda [sig]
    (define-values (_ offset) (ssh-bytes->string sig))

    (subbytes sig offset)))
