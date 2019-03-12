#lang typed/racket/base

(provide (all-defined-out))
(provide ssh-connect ssh-connect/enable-break)

(require "digitama/port.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (ssh-connect/enable-break "192.168.18.118" 22 #:timeout 0.5))
