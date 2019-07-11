#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require "../service.rkt")
(require "../message/connection.rkt")
(require "../assignment/message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [user session]
    (make-ssh-service #:name 'ssh-connection #:user user #:session session #:range ssh-connection-range
                      #:response ssh-connection-response)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self request]
    (values self
            (make-ssh:msg:channel:open:failure #:recipient 0 #:reason 'SSH-OPEN-RESOURCE-SHORTAGE))))
