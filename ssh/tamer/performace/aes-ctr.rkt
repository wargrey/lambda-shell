#lang typed/racket/base

(require racket/file)
(require racket/runtime-path)

(require digimon/format)

(require "../aes.rkt")
(require "../../digitama/algorithm/random.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-runtime-path aes.txt "plain.txt")

(define fsize : Nonnegative-Integer (file-size aes.txt))
(define textsize : Nonnegative-Integer (* (quotient fsize aes-blocksize) aes-blocksize))
(define textpool : Bytes (make-bytes textsize))

(call-with-input-file* aes.txt
  (λ [[/dev/aesin : Input-Port]]
    (void (read-bytes! textpool /dev/aesin 0 textsize))))

(define display-info : (-> Flonum Void)
  (lambda [time0]
    (let ([timespan (- (current-inexact-milliseconds) time0)])
      (printf "~a ~as ~aMB/s~n" (~size textsize)
              (~r (* timespan 0.001) #:precision '(= 3))
              (~r (~MB/s textsize timespan) #:precision '(= 3))))))

(define plaintext : Bytes (bytes-copy textpool))
(define IV : Bytes (ssh-cookie aes-blocksize))
(define key : Bytes (ssh-cookie aes-blocksize))
(define-values (encrypt! decrypt!) (aes-cipher-ctr! IV key))

(collect-garbage)
(collect-garbage)
(collect-garbage)

(printf "encrypting...~n")
(time (let ([time0 (current-inexact-milliseconds)])
        (encrypt! textpool)
        (display-info time0)))

(collect-garbage)
(collect-garbage)
(collect-garbage)

(printf "decrypting...~n")
(time (let ([time0 (current-inexact-milliseconds)])
        (decrypt! textpool)
        (display-info time0)))

(bytes=? textpool plaintext)
