#lang typed/racket/base

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; https://tools.ietf.org/html/rfc4250, The Secure Shell Protocol Assigned Numbers                                        ;;;
;;; https://tools.ietf.org/html/rfc4251, The Secure Shell Protocol Architecture                                            ;;;
;;; https://tools.ietf.org/html/rfc4252, The Secure Shell Authentication Protocol                                          ;;;
;;; https://tools.ietf.org/html/rfc4253, The Secure Shell Transport Layer Protocol                                         ;;;
;;; https://tools.ietf.org/html/rfc4254, The Secure Shell Connection Protocol                                              ;;;
;;;                                                                                                                        ;;;
;;;                                                                                                                        ;;;
;;;                                                                                                                        ;;;
;;; https://tools.ietf.org/html/rfc2104, HMAC: Keyed-Hashing for Message Authentication                                    ;;;
;;; https://tools.ietf.org/html/rfc3526, More Modular Exponential Diffie-Hellman groups for Internet Key Exchange          ;;;
;;; https://tools.ietf.org/html/rfc4344, The Secure Shell Transport Layer Encryption Modes                                 ;;;
;;; https://tools.ietf.org/html/rfc4419, Diffie-Hellman Group Exchange for the Secure Shell Transport Layer Protocol       ;;;
;;; https://tools.ietf.org/html/rfc4432, RSA Key Exchange for the Secure Shell Transport Layer Protocol                    ;;;
;;; https://tools.ietf.org/html/rfc4716, The Secure Shell Public Key File Format                                           ;;;
;;; https://tools.ietf.org/html/rfc5114, Additional Diffie-Hellman Groups for Use with IETF Standards                      ;;;
;;; https://tools.ietf.org/html/rfc6668, The Secure Shell Transport Layer Protocol with SHA-2                              ;;;
;;; https://tools.ietf.org/html/rfc8017, Public-Key Cryptography Standards #1: RSA Cryptography Specifications Version 2.2 ;;;
;;; https://tools.ietf.org/html/rfc8268, More Modular Exponentiation Diffie-Hellman Key Exchange Groups for Secure Shell   ;;;
;;; https://tools.ietf.org/html/rfc8268, Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell Protocol             ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(provide (all-defined-out))

(provide (all-from-out "base.rkt"))
(provide (all-from-out "daemon.rkt" "connection.rkt" "channel.rkt"))

(require "base.rkt")

(require "daemon.rkt")
(require "connection.rkt")
(require "channel.rkt")
