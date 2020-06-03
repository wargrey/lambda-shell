#lang typed/racket/base

(require ssh/base)

(require digimon/collection)
(require digimon/cmdopt)
(require digimon/dtrace)

(require racket/match)

(require "scp/application.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-target-port : (Parameterof Positive-Index) (make-parameter 22))

(define-cmdlet-option scp-flags #: SCP-Flags
  #:args [src ... dest]
  #:usage-help "[unstable, try at your own risk]"
  
  #:once-each
  [[(#\P Port) #:=> cmdopt-string+>port port #: Positive-Index
               ["connect to ~1 on the remote host [default: ~a]" (ssh-target-port)]]])

(define main : (-> (Vectorof String) Void)
  (lambda [argument-list]
    (enter-digimon-zone!)

    (define-values (options λargv) (parse-scp-flags argument-list #:help-output-port (current-output-port)))
    (match-define (list srcs target) (λargv))
    (with-handlers ([exn:fail:user? (λ [[e : exn:fail:user]] (display-scp-flags #:user-error e #:exit 1))])
      (call-with-dtrace
          (λ [] (cond [(null? srcs) (raise-user-error "no sources file specified")]
                      [else (scp (car srcs) target (or (scp-flags-Port options) (ssh-target-port))
                                 (make-ssh-configuration #:pretty-log-packet-level #false))]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (main (current-command-line-arguments)))
