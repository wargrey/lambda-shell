#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "../transport.rkt")
(require "../datatype.rkt")

(require "service.rkt")
(require "assignment.rkt")
(require "diagnostics.rkt")

(require "message/transport.rkt")
(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-daemon-accept : (-> SSH-Listener (-> SSH-Port Void) Void)
  (lambda [sshd serve]
    (define (ssh-port-accept) : Void
      (define sshc : (U SSH-Port Void)
        (with-handlers ([exn? void])
          (ssh-accept sshd)))

      (when (ssh-port? sshc)
        (parameterize ([current-custodian (ssh-custodian sshc)])
          (serve sshc))))
    
    (parameterize ([current-custodian (ssh-custodian sshd)])
      (define &sshcs : (Boxof (Listof Thread)) (box null))

      (with-handlers ([exn:break? void])
        (let sync-accept-serve-loop ()
          (define sshcs : (Listof Thread) (unbox &sshcs))
          (define who : (U SSH-Listener Thread) (apply sync/enable-break (ssh-listener-evt sshd) sshcs))
          
          (set-box! &sshcs
                    (cond [(thread? who) (remove who sshcs)]
                          [else (cons (thread ssh-port-accept) sshcs)]))
          
          (sync-accept-serve-loop)))
        
      (thread-safe-kill (unbox &sshcs))
      (ssh-shutdown sshd))))

(define ssh-daemon-dispatch : (-> SSH-Port SSH-User (SSH-Nameof SSH-Service#) (SSH-Name-Listof* SSH-Service#) Void)
  (lambda [sshd user 1st-service all-services]
    (define session : Bytes (ssh-port-session-identity sshd))
    (define alive-services : (HashTable Symbol SSH-Service)
      (make-hasheq (list (cons (car 1st-service)
                               ((cdr 1st-service) user session)))))

    (with-handlers ([exn:fail? void])
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
