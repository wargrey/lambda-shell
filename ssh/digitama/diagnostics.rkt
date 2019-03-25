#lang typed/racket/base

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax syntax/parse))

(define-type SSH-Error exn:ssh)

(struct exn:ssh exn:fail:network ())
(struct exn:ssh:eof exn:ssh ())
(struct exn:ssh:defense exn:ssh ())
(struct exn:ssh:identification exn:ssh ())
(struct exn:ssh:kex exn:ssh ())

(define ssh-logger-topic : Symbol 'λsh:ssh)

(define-syntax (throw stx)
  (syntax-parse stx
    [(_ st:id rest ...)
     #'(throw [st] rest ...)]
    [(_ [st:id argl ...] src:id peer-name frmt:str v ...)
     #'(let ([errobj (st (format (string-append "~a: [~a]: " frmt) (object-name src) peer-name v ...) (current-continuation-marks) argl ...)])
         (ssh-log-error errobj)
         (raise errobj))]))

(define ssh-raise-timeout-error : (->* (Port Symbol Real) (String) Nothing)
  (lambda [/dev/ssh func seconds [message "timer break"]]
    (raise (make-exn:break (format "~a: ~a: ~a: ~as" (object-name /dev/ssh) func message seconds)
                           (current-continuation-marks)
                           (call-with-escape-continuation
                               (λ [[ec : Procedure]] ec))))))

(define ssh-raise-eof-error : (->* (Port Symbol) (String) Nothing)
  (lambda [/dev/ssh func [message "peer has lost"]]
    (throw exn:ssh:eof /dev/ssh func "~a" message)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-message : (->* (Log-Level String) (#:data Any) #:rest Any Void)
  (lambda [level msgfmt #:data [data #false] . argl]
    (log-message (current-logger)
                 level
                 ssh-logger-topic
                 (if (null? argl) msgfmt (apply format msgfmt argl))
                 data)))

(define ssh-log-error : (->* (SSH-Error) (Log-Level) Void)
  (lambda [errobj [level 'error]]
    (log-message (current-logger)
                 level
                 ssh-logger-topic
                 (format "~a: ~a" (object-name errobj) (exn-message errobj))
                 errobj)))
