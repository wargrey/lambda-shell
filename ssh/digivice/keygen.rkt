#lang racket/base

(require ssh/digitama/algorithm/rsa)

(require racket/tcp)
(require racket/string)
(require racket/cmdline)
(require racket/function)
(require racket/logging)

(require raco/command-name)

(require "keygen/cmdenv.rkt")
(require "keygen/rsa/cmdenv.rkt")
(require "keygen/rsa/keygen.rkt")

(define-values (flag-table --help --unknown)
  (values `((usage-help
             ,(format "[unstable, try at your own risk]~n"))
            (once-any
             [("--17")
              ,(λ [flag] (sshkey-rsa-public-exponent 17))
              ("use 17 as the public exponent")]
             [("--f4")
              ,(λ [flag] (sshkey-rsa-public-exponent 65537))
              (,(format "use the default public exponent [default: ~a]" (sshkey-rsa-public-exponent)))])
            (once-each
             [("-b" "--bits")
              ,(λ [flag bits] (sshkey-rsa-bits (or (string->number bits) (sshkey-rsa-bits))))
              (,(format "specific the number of <bits> in the rsa key [default: ~a]" (sshkey-rsa-bits)) "bits")]
             [("-f")
              ,(λ [flag keyfile] (ssh-keyfile keyfile))
              ("specific the <keyfile>" "keyfile")]
             [("-y")
              ,(λ [flag] (sshkey-rsa-check-private #true))
              ("read and display the <keyfile> as private key")]))
          (λ [-h] (string-replace -h #px"  -- : .+?-h --'." ""))
          (curry eprintf "make: I don't know what does `~a` mean!~n")))

(define main
  (lambda [argument-list]
    (parse-command-line
     (short-program+command-name)
     argument-list
     flag-table
     (λ [!voids] (with-logging-to-port (current-output-port) (λ [] (exit (rsa-keygen-main))) 'debug))
     '()
     (compose1 exit display --help)
     (compose1 exit (const 1) --unknown (curryr string-trim #px"[()]") (curry format "~a") values))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(main (current-command-line-arguments))
