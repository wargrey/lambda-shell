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
    (ssh-connection-application (super-ssh-application #:name name #:session session
                                                       #:range ssh-connection-range
                                                       #:outgoing-log ssh-log-outgoing-message
                                                       #:transmit ssh-connection-transmit
                                                       #:deliver ssh-connection-deliver
                                                       #:data-evt ssh-connection-data-evt
                                                       #:destruct ssh-connection-destruct)
                                (make-hasheq))))

(define ssh-connection-destruct : SSH-Application-Destructor
  (lambda [self]
    (with-asserts ([self ssh-connection-application?])
      (ssh-chport-destruct (ssh-connection-application-ports self)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-transmit : SSH-Application-Transmit
    (lambda [self request rfc]
      (with-asserts ([self ssh-connection-application?])
        (ssh-chport-transmit (ssh-connection-application-ports self)
                             request rfc #false))))

(define ssh-connection-deliver : SSH-Application-Deliver
  (lambda [self bresponse rfc]
    (with-asserts ([self ssh-connection-application?])
      (let ([response (ssh-filter-connection-message bresponse)])
        (unless (not response)
          (ssh-chport-filter* (ssh-connection-application-ports self)
                              response rfc #false))))))

(define ssh-connection-data-evt : SSH-Application-Data-Evt
  (lambda [self rfc]
    (with-asserts ([self ssh-connection-application?])
      (ssh-chport-datum-evt (ssh-connection-application-ports self)))))
