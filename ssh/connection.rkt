#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out))

;; register builtin assignments for services
(require "digitama/assignment/service.rkt")