#lang typed/racket/base

(require digimon/cmdopt)

(require ssh/digitama/algorithm/rsa)

(require racket/logging)

(require "keygen/cmdenv.rkt")
(require "keygen/rsa/cmdenv.rkt")
(require "keygen/rsa/keygen.rkt")

(require "cmdopt/parameter.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-cmdlet-option keygen-flags #: Keygen-Flags
  #:usage-help "[unstable, try at your own risk]"
  #:once-any
  [[(17)       "use 17 as the public exponent"]
   [(f4)       ["use the default public exponent [default: ~a]" (sshkey-rsa-public-exponent)]]]
  #:once-each
  [[(#\b bits) #:=> string->bits-length bits #: Positive-Index
               ["specific the number of ~1 in the rsa key [default: ~a]" (sshkey-rsa-bits)]]
   [(#\f)      keyfile
               "specific the ~1"]
   [(#\y)      "read and display the <keyfile> as private key"]])

(define main : (-> (Vectorof String) Void)
  (lambda [argument-list]
    (define-values (options λargv) (parse-keygen-flags argument-list #:help-output-port (current-output-port)))

    (when (keygen-flags-17 options)
      (sshkey-rsa-public-exponent 17))

    (when (keygen-flags-bits options)
      (sshkey-rsa-bits (keygen-flags-bits options)))

    (with-handlers ([exn:fail:user? (λ [[e : exn:fail:user]] (display-keygen-flags #:user-error e #:exit 1))])
      (with-logging-to-port (current-output-port) (λ [] (exit (rsa-keygen-main (keygen-flags-y options)))) 'debug))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (main (current-command-line-arguments)))
