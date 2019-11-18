#lang typed/racket/base

(require ssh/base)
(require ssh/daemon)

(require digimon/cmdopt)
(require digimon/collection)

(require racket/logging)

(require "cmdopt/parameter.rkt")
(require "cmdopt/common.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-target-port : (Parameterof Nonnegative-Integer) (make-parameter 2222))

(define-cmdlet-option sshd-flags #: SSHD-Flags
  #:usage-help "[unstable, try at your own risk]"
  
  #:once-each
  [[(#\p port) #:=> string->listen-port port #: Nonnegative-Integer
               ["connect to ~1 on the remote host [default: ~a]" (ssh-target-port)]]])

(define main : (-> (Vectorof String) Void)
  (lambda [argument-list]
    (enter-digimon-zone!)

    (define-values (options λargv) (parse-sshd-flags argument-list #:help-output-port (current-output-port)))
    (with-handlers ([exn:fail:user? (λ [[e : exn:fail:user]] (display-sshd-flags #:user-error e #:exit 1))])
      (with-intercepted-logging log-echo
        (λ [] (ssh-daemon (ssh-listen (or (sshd-flags-port options) (ssh-target-port))
                                      #:configuration (make-ssh-configuration #:pretty-log-packet-level #false))))
        'debug))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (main (current-command-line-arguments)))
