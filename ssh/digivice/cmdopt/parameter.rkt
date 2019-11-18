#lang typed/racket/base

(provide (all-defined-out))

(require digimon/cmdopt)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define string->listen-port : (-> String Index)
  (lambda [argv]
    (define port (string->number argv))

    (cond [(and (index? port) (<= port 65535)) port]
          [else (error "expected port number [0, 65535], given" argv)])))

(define string->port : (-> String Positive-Index)
  (lambda [argv]
    (define port (string->number argv))

    (cond [(and (index? port) (<= 1 port) (<= port 65535)) port]
          [else (error "expected port number [1, 65535], given" argv)])))

(define string->bits-length : (-> String Positive-Index)
  (lambda [argv]
    (define size (string->number argv))

    (cond [(and (index? size) (<= 1 size)) size]
          [else (error "expected positive index, given" argv)])))
