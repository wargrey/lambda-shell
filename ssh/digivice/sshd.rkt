#lang racket/base

(require ssh/base)
(require ssh/daemon)
(require ssh/connection)

(require racket/string)
(require racket/cmdline)
(require racket/function)
(require racket/logging)

(require raco/command-name)

(require digimon/collection)
(require digimon/echo)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-target-port (make-parameter 2222))

(define-values (flag-table --help --unknown)
  (values `((usage-help
             ,(format "[unstable, try at your own risk]~n"))
            (once-each
             [("-p" "--port")
              ,(λ [flag port] (ssh-target-port (or (string->number port) (ssh-target-port))))
              (,(format "connect to <port> on the remote host [default: ~a]" (ssh-target-port)) "port")]))
          (λ [-h] (string-replace -h #px"  -- : .+?-h --'." ""))
          (curry eprintf "make: I don't know what does `~a` mean!~n")))

(define main
  (lambda [argument-list]
    (enter-digimon-zone!)
    (parse-command-line
     (short-program+command-name)
     argument-list
     flag-table
     (λ [!voids]
       (with-intercepted-logging
           (λ [log] (case (vector-ref log 0)
                      [(info)    (echof "~a~n" #:fgcolor 'green  (vector-ref log 1))]
                      [(warning) (echof "~a~n" #:fgcolor 'yellow (vector-ref log 1))]
                      [(error)   (echof "~a~n" #:fgcolor 'red    (vector-ref log 1))]
                      [else      (echof "~a~n" #:fgcolor 'gray   (vector-ref log 1))]))
         (λ [] (ssh-daemon (ssh-listen (ssh-target-port) #:configuration (make-ssh-configuration #:pretty-log-packet-level #false))))
         'debug))
     '()
     (compose1 exit display --help)
     (compose1 exit (const 1) --unknown (curryr string-trim #px"[()]") (curry format "~a") values))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(main (current-command-line-arguments))
