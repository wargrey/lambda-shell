#lang typed/racket/base

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax syntax/parse))

(define-type SSH-Error exn:ssh)

(struct exn:ssh exn:fail:network ())
(struct exn:ssh:eof exn:ssh ())
(struct exn:ssh:defence exn:ssh ())
(struct exn:ssh:identification exn:ssh ())
(struct exn:ssh:kex exn:ssh ())

(define current-peer-name : (Parameterof (Option Symbol)) (make-parameter #false))

(define ssh-raise-timeout-error : (->* (Procedure Real) (String) Nothing)
  (lambda [func seconds [message "timer break"]]
    (raise (make-exn:break (format "~a: ~a: ~a: ~as" (current-peer-name) (object-name func) message seconds)
                           (current-continuation-marks)
                           (call-with-escape-continuation
                               (λ [[ec : Procedure]] ec))))))

(define ssh-raise-defence-error : (-> Any String Any * Nothing)
  (lambda [func msgfmt . argl]
    (define errobj : SSH-Error (exn:ssh:defence (ssh-exn-message func msgfmt argl) (current-continuation-marks)))

    (ssh-log-error errobj)
    (raise errobj)))

(define ssh-raise-identification-error : (-> Procedure String Any * Nothing)
  (lambda [func msgfmt . argl]
    (define errobj : SSH-Error (exn:ssh:identification (ssh-exn-message func msgfmt argl) (current-continuation-marks)))

    (ssh-log-error errobj)
    (raise errobj)))

(define ssh-raise-kex-error : (-> Any String Any * Nothing)
  (lambda [func msgfmt . argl]
    (define errobj : SSH-Error (exn:ssh:kex (ssh-exn-message func msgfmt argl) (current-continuation-marks)))

    (ssh-log-error errobj)
    (raise errobj)))

(define ssh-raise-eof-error : (-> Procedure String Any * Nothing)
  (lambda [func msgfmt . argl]
    (define errobj : SSH-Error (exn:ssh:eof (ssh-exn-message func msgfmt argl) (current-continuation-marks)))

    (ssh-log-error errobj)
    (raise errobj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-message : (->* (Log-Level String) (#:data Any) #:rest Any Void)
  (lambda [level msgfmt #:data [data #false] . argl]
    (log-message (current-logger)
                 level
                 #false
                 (if (null? argl) msgfmt (apply format msgfmt argl))
                 data)))

(define ssh-log-error : (->* (SSH-Error) (#:level Log-Level) Void)
  (lambda [errobj #:level [level 'error]]
    (log-message (current-logger)
                 level
                 #false
                 (format "~a: ~a" (object-name errobj) (exn-message errobj))
                 errobj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-exn-message : (-> Any String (Listof Any) String)
  (lambda [func msgfmt argl]
    (string-append (format "~a: ~a: " (current-peer-name) (object-name func))
                   (if (null? argl) msgfmt (apply format msgfmt argl)))))
