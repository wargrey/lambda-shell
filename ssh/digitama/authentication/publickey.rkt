#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/class)

(require "../userauth.rkt")
(require "../fsio/authorized-keys.rkt")
(require "../algorithm/pkcs/key.rkt")

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
             (cond [(ssh:msg:userauth:request:publickey$? request)
                    (let* ([keytype (ssh:msg:userauth:request:publickey-algorithm request)]
                           [rawkey (ssh:msg:userauth:request:publickey-key request)]
                           [key (authorized-key-ref authorized-keys keytype rawkey)])
                      (and (authorized-key? key)
                           (case keytype
                             [(ssh-rsa)
                              (let-values ([(pubkey _) (unsafe-bytes->rsa-public-key (authorized-key-raw key) 7)])
                                (make-ssh:msg:disconnect #:reason 'SSH-DISCONNECT-MAC-ERROR))]
                             [else #false])
                           (or (authorized-key-options key) #true)))]
                   [(ssh:msg:userauth:request:publickey? request)
                    (let* ([keytype (ssh:msg:userauth:request:publickey-algorithm request)]
                           [rawkey (ssh:msg:userauth:request:publickey-key request)]
                           [key (authorized-key-ref authorized-keys keytype rawkey)])
                      (and (authorized-key? key)
                           (ssh-log-message 'debug "partially accepted ~a, continue" (authorized-key-fingerprint key))
                           (make-ssh:msg:userauth:pk:ok #:algorithm keytype #:key rawkey)))]
                   [else #false]))))

    (define/public (abort)
      (void))))
