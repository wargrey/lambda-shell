#lang typed/racket/base

(provide (all-defined-out))

(require racket/math)

(require digimon/struct)

(require "../message.rkt")
(require "../diagnostics.rkt")

(require "../../configuration.rkt")

(define-type SSH-Channel-Reply (U SSH-Message (Listof SSH-Message) Void))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Channel-Constructor (-> Symbol Index SSH-Message SSH-Configuration (U SSH-Channel SSH-Message)))
(define-type SSH-Channel-Destructor (-> SSH-Channel Void))

(define-type SSH-Channel-Response (-> SSH-Channel SSH-Message SSH-Configuration Boolean))
(define-type SSH-Channel-Datum-Evt (-> SSH-Channel Bytes Index Index (U (Evtof SSH-Channel-Reply) Void)))
(define-type SSH-Channel-Notify (-> SSH-Channel SSH-Message SSH-Configuration Void))

(define-type SSH-Channel-Consume
  (case-> [SSH-Channel (U Bytes EOF) Index -> SSH-Channel-Reply]
          [SSH-Channel Bytes Symbol Index -> SSH-Channel-Reply]))

(define-object ssh-channel : SSH-Channel
  ([type : Symbol]
   [name : Symbol]
   [custodian : Custodian])
  ([response : SSH-Channel-Response]
   [consume : SSH-Channel-Consume]
   [datum-evt : SSH-Channel-Datum-Evt void]
   [notify : SSH-Channel-Notify void]
   [destruct : SSH-Channel-Destructor ssh-channel-shutdown-custodian]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-void-method : (-> Any * False)
  (lambda whatever
    #false))

(define ssh-channel-shutdown-custodian : SSH-Channel-Destructor
  (lambda [self]
    (custodian-shutdown-all (ssh-channel-custodian self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-channel-name : (-> Symbol Natural Symbol)
  (lambda [type id]
    (string->symbol (format "~a[0x~a]"
                      (string-titlecase (symbol->string type))
                      (number->string id 16)))))

(define ssh-log-extended-data : (-> Symbol Symbol String Void)
  (lambda [channel type description]
    (case type
      [(SSH-EXTENDED-DATA-STDERR) (ssh-log-message 'error "~a: ~a: ~a" channel type description)]
      [else (ssh-log-message 'info "~a: ~a: ~a" channel type description)])))
