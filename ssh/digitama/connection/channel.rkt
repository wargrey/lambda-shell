#lang typed/racket/base

(provide (all-defined-out))

(require digimon/struct)

(require "../message.rkt")

(require "../../configuration.rkt")

(define-type SSH-Channel-Reply (U SSH-Message (Listof SSH-Message) False))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Constructor (-> Symbol SSH-Message SSH-Configuration (U SSH-Channel SSH-Message)))
(define-type SSH-Channel-Destructor (-> SSH-Channel Void))

(define-type SSH-Channel-Response (-> SSH-Channel SSH-Message SSH-Configuration (Values SSH-Channel Boolean)))
(define-type SSH-Channel-Datum-Evt (-> SSH-Channel Index (Option (Evtof (Pairof SSH-Channel SSH-Channel-Reply)))))

(define-object ssh-channel : SSH-Channel
  ([name : Symbol]
   [envariables : Environment-Variables]
   [custodian : Custodian])
  ([response : SSH-Channel-Response]
   [datum-evt : SSH-Channel-Datum-Evt ssh-channel-no-evt]
   [destruct : SSH-Channel-Destructor ssh-channel-shutdown-custodian]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-no-evt : SSH-Channel-Datum-Evt
  (lambda [self partner-id]
    #false))

(define ssh-channel-shutdown-custodian : SSH-Channel-Destructor
  (lambda [self]
    (custodian-shutdown-all (ssh-channel-custodian self))))
