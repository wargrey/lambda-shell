#lang typed/racket/base

(provide (all-defined-out))

(require "../assignment.rkt")

;; https://tools.ietf.org/html/rfc4250#section-4.3.4
; Symbols in [0xFE000000, 0xFEFFFFFF] are used for conjunction with locally assigned channels;
; Symbols in [0xFE000000, 0xFFFFFFFF] are left for private use.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-symbols SSH-Channel-Failure-Reason #:as Index
  ; https://tools.ietf.org/html/rfc4250#section-4.3
  ([SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1]
   [SSH_OPEN_CONNECT_FAILED                             2]
   [SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3]
   [SSH_OPEN_RESOURCE_SHORTAGE                          4])
  #:fallback SSH-OPEN-CONNECT-FAILED)

(define-ssh-symbols SSH-Channel-Data-Type #:as Index
  ; https://tools.ietf.org/html/rfc4250#section-4.4
  ([SSH_EXTENDED_DATA_STDERR                            1])
  #:fallback SSH_EXTENDED_DATA_STDERR)
