#lang typed/racket/base

(provide (all-defined-out))

(require racket/string)

(require/typed
 racket/date
 [find-seconds (->* (Nonnegative-Integer Nonnegative-Integer Nonnegative-Integer Nonnegative-Integer Nonnegative-Integer Nonnegative-Integer)
                    (Boolean)
                    Nonnegative-Fixnum)])

(require "../fsio/exception.rkt")

(define-type SSH-Option-Value (U String (List String (Option Natural) (Option Natural))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-userauth-option-ref
  : (All (a) (case-> [Symbol (Listof (Pairof Symbol SSH-Option-Value)) -> (Option String)]
                     [Symbol (Listof (Pairof Symbol SSH-Option-Value)) Input-Port (-> String Input-Port (Option Natural) (Option Natural) a) -> (Option a)]))
  (case-lambda
    [(key alist)
     (let ([kv (assq key alist)])
       (and (pair? kv) (ssh-userauth-option-value (cdr kv))))]
    [(key alist source λ->)
     (let ([kv (assq key alist)])
       (and (pair? kv)
            (let-values ([(v line col) (ssh-userauth-option-values (cdr kv))])
              (λ-> v source line col))))]))

(define ssh-userauth-option-map
  : (All (a) (case-> [Symbol (Listof (Pairof Symbol SSH-Option-Value)) -> (Listof String)]
                     [Symbol (Listof (Pairof Symbol SSH-Option-Value)) Input-Port (-> String Input-Port (Option Natural) (Option Natural) a) -> (Listof a)]))
  (case-lambda
    [(key alist)
     (for/list ([kv (in-list alist)] #:when (eq? (car kv) key))
       (ssh-userauth-option-value (cdr kv)))]
    [(key alist source λ->)
     (for/list ([kv (in-list alist)] #:when (eq? (car kv) key))
       (define-values (v line col) (ssh-userauth-option-values (cdr kv)))
       (λ-> v source line col))]))

(define ssh-userauth-option-values : (-> SSH-Option-Value (Values String (Option Natural) (Option Natural)))
  (lambda [v]
    (cond [(string? v) (values v #false #false)]
          [else (values (car v) (cadr v) (caddr v))])))

(define ssh-userauth-option-value : (-> SSH-Option-Value String)
  (lambda [v]
    (cond [(string? v) v]
          [else (car v)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-userauth-check-environment : (-> String Input-Port (Option Natural) (Option Natural) (Pairof String String))
  (lambda [name=value src line col]
    (define size : Index (string-length name=value))
    
    (let split ([i : Nonnegative-Fixnum 0])
      (cond [(>= i size) (throw+exn:ssh:fsio ssh-userauth-check-environment src line col "invalid environment variable")]
            [(not (eq? (string-ref name=value i) #\=)) (split (+ i 1))]
            [(= i 0) (throw+exn:ssh:fsio ssh-userauth-check-environment src line col "invalid environment variable")]
            [else (cons (substring name=value 0 i) (substring name=value (+ i 1) size))]))))

(define ssh-userauth-check-expiry-localtime : (-> String Input-Port (Option Natural) (Option Natural) Natural)
  (lambda [value src line col]
    (define size : Byte 14)
    (define expiration : String
      (case (string-length value)
        [(8) (string-append value "000000")]
        [(12) (string-append value "00")]
        [else value]))

    (with-handlers ([exn:fail? (λ [[e : exn:fail]] (throw+exn:ssh:fsio ssh-userauth-check-environment src line col "invalid expiry time"))])
      (let ([year (string->number (substring expiration 0 4))]
            [month (string->number (substring expiration 4 6))]
            [day (string->number (substring expiration 6 8))]
            [hour (string->number (substring expiration 8 10))]
            [minute (string->number (substring expiration 10 12))]
            [second (string->number (substring expiration 12 14))])
        (find-seconds (assert second byte?) (assert minute byte?) (assert hour byte?)
                      (assert day byte?) (assert month byte?) (assert year index?)
                      #true)))))

(define ssh-userauth-check-port : (-> String Input-Port (Option Natural) (Option Natural) (Pairof (Option String) Index))
  (lambda [name=value src line col]
    (define pattern : (Option (Pairof String (Listof (Option String)))) (regexp-match #px"((.+):)?([*]|\\d+)$" name=value))
    
    (cond [(and pattern (pair? (cdr pattern)) (pair? (cddr pattern)) (pair? (cddr pattern)) (pair? (cdddr pattern)) (string? (cadddr pattern)))
           (let ([port (or (string->number (cadddr pattern)) 0)])
             (cond [(and (index? port) (<= port 65535)) (cons (caddr pattern) port)]
                   [else (throw+exn:ssh:fsio ssh-userauth-check-port src line col "port number out of range")]))]
          [else (throw+exn:ssh:fsio ssh-userauth-check-port src line col "invalid host:port")])))

(define ssh-userauth-check-host:port : (-> String Input-Port (Option Natural) (Option Natural) (Pairof String Index))
  (lambda [host:port src line col]
    (define v : (Pairof (Option String) Index) (ssh-userauth-check-port host:port src line col))
    
    (cond [(string? (car v)) v]
          [else (throw+exn:ssh:fsio ssh-userauth-check-host:port src line col "lack hostname or address")])))

(define ssh-userauth-split : (-> String Input-Port (Option Natural) (Option Natural) (Listof String))
  (lambda [value src line col]
    (map string-trim (string-split value ","))))
