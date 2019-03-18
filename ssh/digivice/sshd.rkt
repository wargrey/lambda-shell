#lang racket/base

(require ssh/transport)

(require racket/tcp)
(require racket/string)
(require racket/cmdline)
(require racket/function)
(require racket/logging)

(require raco/command-name)

(define ssh-target-port (make-parameter 2222))

(define-values (flag-table --help --unknown)
  (values `((usage-help
             ,(format "[unstable, try at your own risk]~n"))
            (once-each
             [("-p" "--port") ,(λ [flag port] (ssh-target-port (or (string->number port) (ssh-target-port))))
                              (,(format "connect to <port> on the remote host [default: ~a]" (ssh-target-port)) "port")]))
          (λ [-h] (string-replace -h #px"  -- : .+?-h --'." ""))
          (curry eprintf "make: I don't know what does `~a` mean!~n")))

(define main
  (lambda [argument-list]
    (parse-command-line
     (short-program+command-name)
     argument-list
     flag-table
     (λ [!voids]
       (with-handlers ([exn? (λ [e] (eprintf "~a~n" (exn-message e)))])
         (define sshd (ssh-listen (ssh-target-port)))
         (with-logging-to-port (current-output-port)
           (λ [] (ssh-port-wait (ssh-accept sshd)))
           'debug)))
     '()
     (compose1 exit display --help)
     (compose1 exit (const 1) --unknown (curryr string-trim #px"[()]") (curry format "~a") values))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(main (current-command-line-arguments))
