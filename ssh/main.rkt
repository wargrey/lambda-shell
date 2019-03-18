#lang typed/racket/base

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; https://tools.ietf.org/html/rfc4250, The Secure Shell Protocol Assigned Numbers              ;;;
;;; https://tools.ietf.org/html/rfc4251, The Secure Shell Protocol Architecture                  ;;;
;;; https://tools.ietf.org/html/rfc4252, The Secure Shell Authentication Protocol                ;;;
;;; https://tools.ietf.org/html/rfc4253, The Secure Shell Transport Layer Protocol               ;;;
;;; https://tools.ietf.org/html/rfc4254, The Secure Shell Connection Protocol                    ;;;
;;;                                                                                              ;;;
;;; https://tools.ietf.org/html/rfc6668, The Secure Shell Transport Layer Protocol with SHA-2    ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(provide (all-defined-out))

(provide SSH-Server-Message-Handler SSH-Message)

(provide (all-from-out "assignment.rkt"))

(require "assignment.rkt")

(require "digitama/transport.rkt")
(require "digitama/transport/identification.rkt")
