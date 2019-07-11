#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

(require "../connection/channel/session.rkt")
(require "../connection/channel/tcpip.rkt")

; datum definition: channel-constructor

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-names #:channel
  ; https://tools.ietf.org/html/rfc4250#section-4.9.1
  ([session         #:=> make-ssh-session-channel]
   [forwarded-tcpip]
   [direct-tcpip]))
