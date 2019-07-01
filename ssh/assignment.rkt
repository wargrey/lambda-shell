#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Kex# SSH-Cipher# SSH-Hostkey# SSH-Compression# SSH-MAC# SSH-Authentication#)
(provide ssh-cipher-algorithms ssh-kex-algorithms ssh-hostkey-algorithms ssh-mac-algorithms ssh-compression-algorithms ssh-authentication-methods)
(provide define-ssh-symbols define-ssh-names define-ssh-namebase)

(require "digitama/assignment.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Symbols in [0xFE000000, 0xFFFFFFFF] are left for private use.
(define-ssh-symbols SSH-Disconnection-Reason : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.2.2
  ([SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          1]
   [SSH_DISCONNECT_PROTOCOL_ERROR                       2]
   [SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  3]
   [SSH_DISCONNECT_RESERVED                             4]
   [SSH_DISCONNECT_MAC_ERROR                            5]
   [SSH_DISCONNECT_COMPRESSION_ERROR                    6]
   [SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                7]
   [SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       8]
   [SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              9]
   [SSH_DISCONNECT_CONNECTION_LOST                     10]
   [SSH_DISCONNECT_BY_APPLICATION                      11]
   [SSH_DISCONNECT_TOO_MANY_CONNECTIONS                12]
   [SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              13]
   [SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      14]
   [SSH_DISCONNECT_ILLEGAL_USER_NAME                   15]))

(define-ssh-symbols SSH-Channel-Failure-Reason : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.3
  ([SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1]
   [SSH_OPEN_CONNECT_FAILED                             2]
   [SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3]
   [SSH_OPEN_RESOURCE_SHORTAGE                          4]))

(define-ssh-symbols SSH-Channel-Data-Type : Index
  ; https://tools.ietf.org/html/rfc4250#section-4.4
  ([SSH_EXTENDED_DATA_STDERR                            1]))
