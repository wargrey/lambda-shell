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
(define ssh-daemon-accept : (-> SSH-Listener (-> SSH-Port Void) Void)
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

(define ssh-daemon-dispatch : (-> SSH-Port SSH-User (SSH-Nameof SSH-Service#) (SSH-Name-Listof* SSH-Service#) Void)
  (lambda [sshd user 1st-service all-services]
    (define session : Bytes (ssh-port-session-identity sshd))
    (define alive-services : (HashTable Symbol SSH-Service)
      (make-hasheq (list (cons (car 1st-service)
                               ((cdr 1st-service) user session)))))

    (with-handlers ([exn? void])
      (let read-dispatch-loop ()
        (define datum : SSH-Datum (sync/enable-break (ssh-port-datum-evt sshd)))

        (unless (ssh-eof? datum)
          (cond [(bytes? datum) (void)]
                
                [(ssh:msg:service:request? datum)
                 (define maybe-service (assq (ssh:msg:service:request-name datum) all-services))
                 
                 (when (pair? maybe-service)
                   (void))
                 
                 (void)])
        
          (read-dispatch-loop))))))
