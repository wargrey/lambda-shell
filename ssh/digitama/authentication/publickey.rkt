#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require "../userauth.rkt")
(require "../fsio/authorized-keys.rkt")
(require "../algorithm/hostkey/rsa.rkt")

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
(define make-ssh-publickey-userauth : SSH-Userauth-Constructor
  (lambda [session-id]
    (make-ssh-userauth session-id 'publickey
                       ssh-publickey-request ssh-publickey-response
                       #false)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-publickey-request : SSH-Userauth-Request
  (lambda [self username service response]
    (or response (make-ssh:msg:userauth:request #:username username #:service service #:method 'publickey))))

(define ssh-publickey-response : SSH-Userauth-Response
  (lambda [self request username service]
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
                      (let ([message (bytes-append (ssh-bstring->bytes (ssh-userauth-session-id self)) (ssh:msg:userauth:request:publickey->bytes request))]
                            [signature (ssh:msg:userauth:request:publickey$-signature request)])
                        (and (case keytype
                               [(ssh-rsa rsa-sha2-256)
                                (let-values ([(pubkey) (rsa-bytes->public-key (authorized-key-raw key))]
                                             [(algname sigoff) (rsa-bytes->signature-offset signature)])
                                  (and (eq? keytype algname)
                                       (ssh-rsa-verify pubkey message signature sigoff keytype)
                                       (ssh-log-message 'debug "verified ~a" (authorized-key-fingerprint key))))]
                               [else #false])
                             (or (authorized-key-options key) #true))))))))))
