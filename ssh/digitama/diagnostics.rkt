#lang typed/racket/base

(provide (all-defined-out))

(require digimon/exception)

(struct exn:ssh exn:fail () #:type-name SSH-Error)

(struct exn:ssh:eof exn:ssh ([reason : Symbol]))

(define current-peer-name : (Parameterof (Option Symbol)) (make-parameter #false))

(define ssh-raise-timeout-error : (->* (Procedure Real) (String) Nothing)
  (lambda [func seconds [message "timer break"]]
    (raise (make-exn:break (format "~a: ~a: ~a: ~as" (current-peer-name) (object-name func) message seconds)
                           (current-continuation-marks)
                           (call-with-escape-continuation
                               (λ [[ec : Procedure]] ec))))))

(define-exception exn:ssh:defence exn:ssh () (ssh-exn-message))
(define-exception exn:ssh:identification exn:ssh () (ssh-exn-message))
(define-exception exn:ssh:kex exn:ssh () (ssh-exn-message))
(define-exception exn:ssh:kex:hostkey exn:ssh:kex () (ssh-exn-message))
(define-exception exn:ssh:mac exn:ssh () (ssh-exn-message))
(define-exception exn:ssh:fsio exn:fail:filesystem () (ssh-exn-fsio-message [/dev/stdin : Input-Port] [line : (Option Natural)] [col : (Option Natural)]))

(define ssh-raise-eof-error : (->* (Procedure Symbol String) (#:logging? Boolean) #:rest Any Nothing)
  (lambda [func reason #:logging? [logging? #true] msgfmt . argl]
    (define errobj : SSH-Error
      (exn:ssh:eof (ssh-exn-message func (default-exn-message msgfmt argl))
                   (current-continuation-marks) reason))

    (when logging?
      (default-log-error errobj))
    
    (raise errobj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-message : (->* (Log-Level String) (#:data Any #:with-peer-name? Boolean) #:rest Any Void)
  (lambda [level msgfmt #:data [data #false] #:with-peer-name? [peername? #true] . argl]
    (define message-raw : String (if (null? argl) msgfmt (apply format msgfmt argl)))
    
    (log-message (current-logger)
                 level
                 #false
                 (cond [(not peername?) message-raw]
                       [else (let ([peer (current-peer-name)])
                               (cond [(not peer) message-raw]
                                     [else (format "~a: ~a" peer message-raw)]))])
                 data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-exn-message : (-> Any String String)
  (lambda [func msg]
    (let ([peername (current-peer-name)]
          [srcname (object-name func)])
      (cond [(and peername srcname) (string-append (format "~a: ~a: " peername srcname) msg)]
            [(or peername srcname) => (λ [name] (string-append (format "~a: " name) msg))]
            [else msg]))))

(define ssh-exn-fsio-message : (-> Any Input-Port (Option Natural) (Option Natural) String String)
  (lambda [func /dev/stdin line col msg]
    (cond [(and line col) (ssh-exn-message func (string-append (format "~a:~a:~a: " (object-name /dev/stdin) line col) msg))]
          [else (ssh-exn-message func (string-append (format "~a: " (object-name /dev/stdin)) msg))])))
