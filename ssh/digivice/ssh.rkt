#lang typed/racket/base

(require ssh/base)

(require digimon/cmdopt)
(require digimon/dtrace)
(require digimon/collection)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-target-port : (Parameterof Positive-Integer) (make-parameter 22))

(define-cmdlet-option ssh-flags #: SSH-Flags
  #:usage-help "[unstable, try at your own risk]"
  #:args [hostname]
  
  #:once-each
  [[(#\p port) #:=> cmdopt-string+>port port #: Positive-Integer
               ["connect to ~1 on the remote host [default: ~a]" (ssh-target-port)]]])

(define main : (-> (Vectorof String) Void)
  (lambda [argument-list]
    (enter-digimon-zone!)

    (define-values (options λargv) (parse-ssh-flags argument-list #:help-output-port (current-output-port)))
    (with-handlers ([exn:fail:user? (λ [[e : exn:fail:user]] (display-ssh-flags #:user-error e #:exit 1))])
      (call-with-dtrace
        (λ [] (void (ssh-connect (car (λargv)) (or (ssh-flags-port options) (ssh-target-port)))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (main (current-command-line-arguments)))
