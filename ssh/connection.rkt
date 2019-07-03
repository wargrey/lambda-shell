#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))

(require racket/port)

(require "digitama/diagnostics.rkt")
(require "digitama/message/connection.rkt")
(require "digitama/connection/message.rkt")

(require "datatype.rkt")
(require "transport.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-listen : (-> SSH-Port (U SSH-EOF Void))
  (lambda [sshc]
    (let listen ([datum-evt : (Evtof SSH-Datum) (ssh-connection-datum-evt sshc)])
      (define datum : SSH-Datum (sync/enable-break datum-evt))
      
      (cond [(ssh-eof? datum) datum]
            [else (ssh-port-write sshc (make-ssh:msg:channel:open:failure #:recipient 0 #:reason 'SSH-OPEN-RESOURCE-SHORTAGE))]))))
