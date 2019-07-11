#lang typed/racket/base

(provide (all-defined-out))

(require typed/racket/unsafe)

(unsafe-require/typed
 racket/base
 [wrap-evt (All (a) (-> Log-Receiver (-> (Immutable-Vector Log-Level String a (Option Symbol)) a) (Evtof a)))])

(define-type (SSH-Stdout a) Logger)
(define-type (SSH-Stdin a) Log-Receiver)

;;; NOTE
;; Racket logging facility is much powerful than usual logging facilities since,
;;  It is a many-to-many multiple dispatch mechansim, albeit only one-to-one dispatch is used here;
;;  It is a primitive service provided by the Racket Virtual Machine directly and therefore is very efficient.
;;
;; That is the reason why the logging facility is chosen to work as the asynchronous IO
;;  between the transport layer and userland layers.
;;
;; Besides, Racket pipe with special datum enabled was a good choice as well except,
;;  It cannot propagate bytes as special data directly and continuously.
;;  (Actually the writer is okay, but the reader is confused after receiving the first bytes datum.)
;;  Maybe it is a bug, nonetheless, it is less efficient than the logging facility per se.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-stdio : (-> Symbol (Values (SSH-Stdin Port) (SSH-Stdout Port)))
  (lambda [name]
    (define /dev/sshout : Logger (make-logger name #false))
    (define /dev/sshin : Log-Receiver (make-log-receiver /dev/sshout 'debug name))

    (values /dev/sshin /dev/sshout)))

(define ssh-stdin-evt : (All (a) (-> (SSH-Stdin Port) (Evtof a)))
  (lambda [/dev/sshin]
    ((inst wrap-evt a) /dev/sshin (λ [info] (vector-ref info 2)))))

(define ssh-stdout-propagate : (->* ((SSH-Stdout Port) Any) (String #:level Log-Level) Void)
  (lambda [/dev/sshout msg [description ""] #:level [level 'info]]
    (log-message /dev/sshout level description msg)))
