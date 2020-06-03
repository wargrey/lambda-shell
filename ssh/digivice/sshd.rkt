#lang typed/racket/base

(require ssh/base)
(require ssh/daemon)

(require digimon/cmdopt)
(require digimon/dtrace)
(require digimon/collection)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-target-port : (Parameterof Nonnegative-Integer) (make-parameter 2222))

(define-cmdlet-option sshd-flags #: SSHD-Flags
  #:usage-help "[unstable, try at your own risk]"
  
  #:once-each
  [[(#\p port) #:=> cmdopt-string+>port port #: Nonnegative-Integer
               ["connect to ~1 on the remote host [default: ~a]" (ssh-target-port)]]])

(define main : (-> (Vectorof String) Void)
  (lambda [argument-list]
    (enter-digimon-zone!)

    (define-values (options λargv) (parse-sshd-flags argument-list #:help-output-port (current-output-port)))
    (with-handlers ([exn:fail:user? (λ [[e : exn:fail:user]] (display-sshd-flags #:user-error e #:exit 1))])
      (call-with-dtrace
          (λ [] (ssh-daemon (ssh-listen (or (sshd-flags-port options) (ssh-target-port))
                                        #:configuration (make-ssh-configuration #:pretty-log-packet-level #false))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (main (current-command-line-arguments)))
