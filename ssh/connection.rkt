#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))

;; register builtin assignments for services and applications
(require "digitama/assignment/service.rkt")
(require "digitama/assignment/application.rkt")

;; register builtin assignments for channels
(require "digitama/assignment/channel.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
