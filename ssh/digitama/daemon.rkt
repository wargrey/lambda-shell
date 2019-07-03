#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "../transport.rkt")
(require "../datatype.rkt")
(require "../assignment.rkt")

(require "service.rkt")
(require "diagnostics.rkt")

(require "message/transport.rkt")
(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-daemon-accept : (-> SSH-Daemon (-> SSH-Port Void) Void)
  (lambda [sshd serve]
    (parameterize ([current-custodian (ssh-custodian sshd)])
      (let accept-serve-loop ([sshcs : (Listof Thread) null])
        (with-handlers ([exn:break? void])
          (define maybe-sshc : (U Thread Void)
            (with-handlers ([exn:fail? (λ [[e : exn]] (eprintf "~a~n" (exn-message e)))])
              (let ([sshc (ssh-accept sshd)])
                (parameterize ([current-custodian (ssh-custodian sshc)])
                  (thread (λ [] (serve sshc)))))))
          (accept-serve-loop (if (thread? maybe-sshc) (cons maybe-sshc sshcs) sshcs)))

        (thread-safe-kill sshcs)
        (ssh-shutdown sshd)))))

(define ssh-daemon-dispatch : (-> SSH-Port (Pairof SSH-User (SSH-Nameof SSH-Service#)) (SSH-Name-Listof* SSH-Service#) Void)
  (lambda [sshd user+1st-service all-services]
    (let read-dispatch-loop ([services : (Pairof SSH-Service (Listof SSH-Service)) (list ((cddr user+1st-service) (car user+1st-service)))]
                             [candidates : (SSH-Name-Listof* SSH-Service#) (ssh-names-remove (cadr user+1st-service) all-services)])
      (define datum : SSH-Datum (sync/enable-break (ssh-port-datum-evt sshd)))

      (define-values (services++ candidates--)
        (cond [(bytes? datum) (values services candidates)]

              [(ssh:msg:service:request? datum)
               (values services candidates)]

              [(ssh-eof? datum) datum (values null candidates)]
              [else #| dead code |# (values services candidates)]))

      (cond [(pair? services++) (read-dispatch-loop services++ candidates--)]
            [else (void 'shutdown)]))))
