#lang typed/racket/base

(provide (all-defined-out))

(define current-peer-name : (Parameterof (Option Symbol)) (make-parameter #false))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-log-message : (->* (Log-Level String) (#:data Any #:with-peer-name? Boolean) #:rest Any Void)
  (lambda [level msgfmt #:data [data #false] #:with-peer-name? [peername? #true] . argl]
    (define message-raw : String (apply format msgfmt argl))
    
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
