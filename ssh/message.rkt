#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4250
;;; https://tools.ietf.org/html/rfc4251

(provide (all-defined-out))
(provide SSH-Message Unsafe-SSH-Bytes->Message)
(provide ssh-message? ssh-message-undefined?)
(provide ssh-message-number ssh-message-name ssh-message-payload-number)
(provide define-ssh-messages define-ssh-case-messages define-ssh-shared-messages)

(require "datatype.rkt")

(require "digitama/message.rkt")

(require (for-syntax racket/base))
(require (for-syntax racket/syntax))

(define-syntax (define-ssh-message-range stx)
  (syntax-case stx [:]
    [(_ type idmin idmax comments ...)
     (with-syntax ([ssh-range-payload? (format-id #'type "ssh-~a-payload?" (syntax-e #'type))]
                   [ssh-range-message? (format-id #'type "ssh-~a-message?" (syntax-e #'type))]
                   [ssh-bytes->range-message (format-id #'type "ssh-bytes->~a-message" (syntax-e #'type))]
                   [ssh-bytes->range-message* (format-id #'type "ssh-bytes->~a-message*" (syntax-e #'type))])
       #'(begin (define ssh-range-payload? : (->* (Bytes) (Index) Boolean)
                  (lambda [src [offset 0]]
                    (<= idmin (ssh-message-payload-number src offset) idmax)))

                (define ssh-range-message? : (-> Any Boolean : #:+ SSH-Message)
                  (lambda [self]
                    (and (ssh-message? self)
                         (<= idmin (ssh-message-number self) idmax))))
                
                (define ssh-bytes->range-message : (->* (Bytes) (Index #:group (Option Symbol)) (values (Option SSH-Message) Natural))
                  (lambda [bmsg [offset 0] #:group [group #false]]
                    (cond [(<= idmin (bytes-ref bmsg offset) idmax) (ssh-bytes->message bmsg offset #:group group)]
                          [else (values #false offset)])))

                (define ssh-bytes->range-message* : (->* (Bytes) (Index #:group (Option Symbol)) (Option SSH-Message))
                  (lambda [bmsg [offset 0] #:group [group #false]]
                    (define-values (maybe-message end-index) (ssh-bytes->message bmsg offset #:group group))
                    maybe-message))))]))

;; https://tools.ietf.org/html/rfc4251#section-7
(define-ssh-message-range transport        1  49   Transport layer protocol)
(define-ssh-message-range authentication  50  79   User authentication protocol)
(define-ssh-message-range connection      80 127   Connection protocol)
(define-ssh-message-range client         128 191   Reserved for client protocols)
(define-ssh-message-range private        192 255   Local extensions for private use)

(define-ssh-message-range generic          1  19   Transport layer generic (e.g., disconnect, ignore, debug, etc.))
(define-ssh-message-range key-exchange    30  49   Key exchange method specific (numbers can be reused for different authentication methods))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-message-length : (-> SSH-Message Natural)
  (lambda [self]
    ((hash-ref ssh-message-length-database (ssh-message-name self)) self)))

(define ssh-message->bytes : (SSH-Datum->Bytes SSH-Message)
  (case-lambda
    [(self) ((hash-ref ssh-message->bytes-database (ssh-message-name self)) self)]
    [(self pool) (ssh-message->bytes self pool 0)]
    [(self pool offset) ((hash-ref ssh-message->bytes-database (ssh-message-name self)) self pool offset)]))

(define ssh-bytes->message : (->* (Bytes) (Index #:group (Option Symbol)) (Values SSH-Message Natural))
  (lambda [bmsg [offset 0] #:group [group #false]]
    (define id : Byte (ssh-message-payload-number bmsg offset))
    (define-values (msg end)
      (let ([unsafe-bytes->message (hash-ref ssh-bytes->message-database id (λ [] #false))])
        (cond [(and unsafe-bytes->message) (unsafe-bytes->message bmsg offset)]
              [else (let ([bytes->message (ssh-bytes->shared-message group id)])
                      (cond [(not bytes->message) (values (ssh-undefined-message id) offset)]
                            [else (bytes->message bmsg offset)]))])))
    
    (let message->conditional-message ([msg : SSH-Message msg]
                                       [end : Natural end])
      (define name : Symbol (ssh-message-name msg))
      (cond [(hash-has-key? ssh-bytes->case-message-database name)
             (let ([case-info (hash-ref ssh-bytes->case-message-database name)])
               (define key : Any (unsafe-struct*-ref msg (car case-info)))
               (define bytes->case-message : (Option Unsafe-SSH-Bytes->Message) (hash-ref (cdr case-info) key (λ [] #false)))
               (cond [(and bytes->case-message) (call-with-values (λ [] (bytes->case-message bmsg offset)) message->conditional-message)]
                     [else (values msg end)]))]
            [else (values msg end)]))))

(define ssh-bytes->message* : (->* (Bytes) (Index #:group (Option Symbol)) SSH-Message)
  (lambda [bmsg [offset 0] #:group [group #false]]
    (define-values (message end-index) (ssh-bytes->message bmsg offset #:group group))
    message))
