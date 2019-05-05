#lang racket/base

(require ssh/base)
(require ssh/authentication)

(require racket/string)
(require racket/cmdline)
(require racket/function)
(require racket/logging)

(require raco/command-name)

(require digimon/collection)

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

(define sshd-serve
  (lambda [sshc services]
    (parameterize ([current-peer-name (ssh-port-peer-name sshc)])
      (with-handlers ([exn:fail? (λ [e] (ssh-shutdown sshc 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
        (define maybe-user (ssh-user-authenticate sshc services))
        
        (when (ssh-user? maybe-user)
          (let sync-read-display-loop ()
            (define datum (sync/enable-break (ssh-port-datum-evt sshc)))
            (unless (ssh-eof? datum)
              (sync-read-display-loop)))))
      
      (ssh-port-wait sshc))))

(define main
  (lambda [argument-list]
    (enter-digimon-zone!)
    (parse-command-line
     (short-program+command-name)
     argument-list
     flag-table
     (λ [!voids]
       (with-logging-to-port (current-output-port)
         (λ [] (let ([sshd (ssh-listen (ssh-target-port) #:configuration (make-ssh-configuration #:pretty-log-packet-level 'info))])
                 (parameterize ([current-custodian (ssh-custodian sshd)])
                   (with-handlers ([exn:break? (λ [e] (ssh-shutdown sshd))]
                                   [exn? (λ [e] (eprintf "~a~n" (exn-message e)))])
                     (let accept-server-loop ()
                       (with-handlers ([exn:fail? (λ [e] (eprintf "~a~n" (exn-message e)))])
                         (let ([sshc (ssh-accept sshd)])
                           (thread-wait (thread (λ [] (sshd-serve sshc (ssh-daemon-services sshd)))))))
                       #;(accept-server-loop))))))
         'debug))
     '()
     (compose1 exit display --help)
     (compose1 exit (const 1) --unknown (curryr string-trim #px"[()]") (curry format "~a") values))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(main (current-command-line-arguments))
