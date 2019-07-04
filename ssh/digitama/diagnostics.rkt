#lang typed/racket/base

(provide (all-defined-out))

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-ssh-error stx)
  (syntax-case stx [: lambda λ]
    [(_ exn:ssh:sub parent (fields ...) #:->* (Extra-Type ...) (Optional-Type ...) (lambda [args ... #:+ fmt argl] body ...))
     (with-syntax* ([make-exn (format-id #'exn:ssh:sub "make-~a" (syntax-e #'exn:ssh:sub))]
                    [make+exn (format-id #'exn:ssh:sub "make+~a" (syntax-e #'exn:ssh:sub))]
                    [throw-exn (format-id #'exn:ssh:sub "throw-~a" (syntax-e #'exn:ssh:sub))]
                    [throw+exn (format-id #'exn:ssh:sub "throw+~a" (syntax-e #'exn:ssh:sub))])
       #'(begin (struct exn:ssh:sub parent (fields ...))

                (define make-exn : (->* (Extra-Type ... String) (Optional-Type ...) #:rest Any exn:ssh:sub)
                  (lambda [args ... fmt . argl]
                    body ...))

                (define make+exn : (->* (Extra-Type ... String) (Optional-Type ...) #:rest Any exn:ssh:sub)
                  (lambda [args ... fmt . argl]
                    (let ([errobj (apply make-exn args ... fmt argl)])
                      (ssh-log-error errobj)
                      errobj)))

                (define throw-exn : (->* (Extra-Type ... String) (Optional-Type ...) #:rest Any Nothing)
                  (lambda [args ... fmt . argl]
                    (raise (apply make-exn args ... fmt argl))))

                (define throw+exn : (->* (Extra-Type ... String) (Optional-Type ...) #:rest Any Nothing)
                  (lambda [args ... fmt . argl]
                    (raise (apply make+exn args ... fmt argl))))))]
    [(_ exn:ssh:sub parent (fields ...) #:->* (Extra-Type ...) (Optional-Type ...) (λ [args ... #:+ fmt argl] body ...))
     #'(define-ssh-error exn:ssh:sub parent (fields ...) #:->* (Extra-Type ...) (Optional-Type ...) (lambda [args ... #:+ fmt argl] body ...))]))

(struct exn:ssh exn:fail () #:type-name SSH-Error)

(struct exn:ssh:eof exn:ssh ([reason : Symbol]))

(define current-peer-name : (Parameterof (Option Symbol)) (make-parameter #false))

(define ssh-raise-timeout-error : (->* (Procedure Real) (String) Nothing)
  (lambda [func seconds [message "timer break"]]
    (raise (make-exn:break (format "~a: ~a: ~a: ~as" (current-peer-name) (object-name func) message seconds)
                           (current-continuation-marks)
                           (call-with-escape-continuation
                               (λ [[ec : Procedure]] ec))))))

(define-ssh-error exn:ssh:defence exn:ssh () #:->* (Any) ()
  (lambda [func #:+ msgfmt argl]
    (exn:ssh:defence (ssh-exn-message func msgfmt argl)
                     (current-continuation-marks))))

(define-ssh-error exn:ssh:identification exn:ssh () #:->* (Any) ()
  (lambda [func #:+ msgfmt argl]
    (exn:ssh:identification (ssh-exn-message func msgfmt argl)
                            (current-continuation-marks))))

(define-ssh-error exn:ssh:kex exn:ssh () #:->* (Any) ()
  (lambda [func #:+ msgfmt argl]
    (exn:ssh:kex (ssh-exn-message func msgfmt argl)
                 (current-continuation-marks))))

(define-ssh-error exn:ssh:kex:hostkey exn:ssh:kex () #:->* (Any) ()
  (lambda [func #:+ msgfmt argl]
    (exn:ssh:kex:hostkey (ssh-exn-message func msgfmt argl)
                         (current-continuation-marks))))

(define-ssh-error exn:ssh:mac exn:ssh () #:->* (Any) ()
  (lambda [func #:+ msgfmt argl]
    (exn:ssh:mac (ssh-exn-message func msgfmt argl)
                 (current-continuation-marks))))


(define-ssh-error exn:ssh:fsio exn:ssh () #:->* (Any Any (Option Natural) (Option Natural)) ()
  (lambda [func /dev/stdin line col #:+ msgfmt argl]
    (exn:ssh:fsio (cond [(and line col) (ssh-exn-message func (string-append "~a:~a:~a: " msgfmt) (list* /dev/stdin line col argl))]
                        [else (ssh-exn-message func (string-append "~a: " msgfmt) (list* /dev/stdin argl))])
                  (current-continuation-marks))))

(define ssh-raise-eof-error : (->* (Procedure Symbol String) (#:logging? Boolean) #:rest Any Nothing)
  (lambda [func reason #:logging? [logging? #true] msgfmt . argl]
    (define errobj : SSH-Error
      (exn:ssh:eof (ssh-exn-message func msgfmt argl)
                   (current-continuation-marks) reason))

    (when logging?
      (ssh-log-error errobj))
    
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
    (define message : String (if (null? argl) msgfmt (apply format msgfmt argl)))
    
    (let ([peername (current-peer-name)]
          [srcname (object-name func)])
      (cond [(and peername srcname) (string-append (format "~a: ~a: " peername srcname) message)]
            [(or peername srcname) => (λ [name] (string-append (format "~a: " name) message))]
            [else message]))))
