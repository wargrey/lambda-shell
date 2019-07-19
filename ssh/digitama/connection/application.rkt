#lang typed/racket/base

(provide (all-defined-out))

(require "message.rkt")
(require "chport.rkt")

(require "../service.rkt")

(require "../assignment/message.rkt")

(struct ssh-connection-application ssh-application
  ([ports : SSH-Channel-Port])
  #:type-name SSH-Connection-Application)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-connection-application : SSH-Application-Constructor
  (lambda [name session]
    (ssh-connection-application (super-ssh-application #:name name #:session session #:range ssh-connection-range
                                                       #:guard ssh-connection-guard #:deliver ssh-connection-deliver
                                                       #:destruct ssh-connection-destruct)
                                (make-hasheq))))

(define ssh-connection-destruct : SSH-Application-Destructor
  (lambda [self]
    (with-asserts ([self ssh-connection-application?])
      (ssh-chport-destruct (ssh-connection-application-ports self)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-guard : SSH-Application-Guard
  (lambda [self request rfc]
    (with-asserts ([self ssh-connection-application?])
      (ssh-chport-filter (ssh-connection-application-ports self) request rfc))))

(define ssh-connection-deliver : SSH-Application-Deliver
  (lambda [self bresponse rfc]
    (with-asserts ([self ssh-connection-application?])
      (let ([response (ssh-filter-connection-message bresponse)])
        (and response
             (ssh-chport-filter (ssh-connection-application-ports self) response rfc))))))
