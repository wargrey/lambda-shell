#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")
(require "chport.rkt")

(require "../service.rkt")

(require "../assignment/message.rkt")

(struct ssh-connection-service ssh-service
  ([ports : SSH-Channel-Port])
  #:type-name SSH-Connection-Service)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-service : SSH-Service-Constructor
  (lambda [name user session]
    (ssh-connection-service (super-ssh-service #:name name #:user user #:session session #:range ssh-connection-range
                                               #:response ssh-connection-response #:push-evt ssh-connection-push-evt
                                               #:destruct ssh-connection-destruct)
                            (make-hasheq))))

(define ssh-connection-destruct : SSH-Service-Destructor
  (lambda [self]
    (with-asserts ([self ssh-connection-service?])
      (ssh-chport-destruct (ssh-connection-service-ports self)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-response : SSH-Service-Response
  (lambda [self brequest rfc]
    (with-asserts ([self ssh-connection-service?])
      (let ([request (ssh-filter-connection-message brequest)])
        (and request
             (ssh-chport-filter (ssh-connection-service-ports self)
                                request rfc))))))

(define ssh-connection-push-evt : SSH-Service-Push-Evt
  (lambda [self rfc]
    (with-asserts ([self ssh-connection-service?])
      (ssh-chport-datum-evt (ssh-connection-service-ports self)))))
