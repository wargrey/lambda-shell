#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252#section-7

(provide (all-defined-out))

(require "message.rkt")

(require "../message.rkt")
(require "../service.rkt")

(require "../message/connection.rkt")
(require "../assignment/message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [user session rfc]
    (make-ssh-service #:name 'ssh-connection #:user user #:session session #:preference rfc
                      #:range ssh-connection-range #:log-outgoing ssh-log-outgoing-message
                      #:response ssh-connection-response)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest]
    (define request : (Option SSH-Message) (ssh-filter-connection-message brequest))
    (values self
            (make-ssh:msg:channel:open:failure #:recipient 0 #:reason 'SSH-OPEN-RESOURCE-SHORTAGE))))
