#lang typed/racket/base

(provide (all-defined-out))

(require "../channel.rkt")

(require "../../message.rkt")

(require "../../message/connection.rkt")

(require "../../../datatype.rkt")

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require (for-syntax "../../message/connection.rkt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-case-messages SSH-MSG-CHANNEL-OPEN
  ; https://tools.ietf.org/html/rfc4254#section-6.1
  [SESSION  #:type 'session  ()])

(define-ssh-case-messages SSH-MSG-CHANNEL-REQUEST
  ; https://tools.ietf.org/html/rfc4254#section-6.2
  [PTY-REQ    #:type 'pty-req    ([TERM-value : String] [cols : Index] [rows : Index] [width : Index] [height : Index] [modes : Bytes])]
  ; https://tools.ietf.org/html/rfc4254#section-6.4
  [ENV        #:type 'env        ([name : Bytes] [value : Bytes])]
  ; https://tools.ietf.org/html/rfc4254#section-6.5
  [SHELL      #:type 'shell      ()]
  [EXEC       #:type 'exec       ([command : String])]
  [SUBSYSTEM  #:type 'subsystem  ([name : Symbol])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-session-channel : SSH-Channel-Constructor
  (lambda [name msg rfc]
    (with-asserts ([msg ssh:msg:channel:open:session?])
      (make-ssh-channel #:name name))))
