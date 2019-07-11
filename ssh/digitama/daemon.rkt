#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "../transport.rkt")
(require "../datatype.rkt")

(require "service.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "transport.rkt")
(require "diagnostics.rkt")

(require "message/transport.rkt")
(require "authentication/user.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-daemon-accept : (-> SSH-Listener (-> SSH-Port Void) Void)
  (lambda [sshd serve]
    (define (ssh-port-accept) : Void
      (define sshc : (U SSH-Port Void)
        (with-handlers ([exn:fail? (λ [[e : exn]] (displayln (exn-message e) (current-error-port)))]
                        [exn:break? void])
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
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (exn-message e)))])
      (let read-dispatch-serve-loop ()
        (define datum : SSH-Datum (sync/enable-break (ssh-port-datum-evt sshd)))

        (unless (ssh-eof? datum)
          (cond [(bytes? datum)
                 (define mid : Byte (ssh-message-payload-number datum))
                 (let dispatch ([services (hash-values alive-services)])
                   (cond [(null? services) (ssh-port-write sshd (make-ssh:msg:unimplemented #:number mid))]
                         [else (let*-values ([(service) (car services)]
                                             [(name) (ssh-service-name service)]
                                             [(idmin idmax) (let ([r (ssh-service-range service)]) (values (car r) (cdr r)))])
                                 (cond [(not (<= idmin mid idmax)) (dispatch (cdr services))]
                                       [else (let-values ([(state response) (ssh-service.response service datum)])
                                               (hash-set! alive-services (ssh-service-name state) state)
                                               (for ([resp (if (list? response) (in-list response) (in-value response))])
                                                 (if (<= idmin (ssh-message-number resp) idmax)
                                                     (ssh-port-write sshd resp)
                                                     (ssh-port-ignore sshd resp))))]))]))]
                
                [(ssh:msg:service:request? datum)
                 (define service : Symbol (ssh:msg:service:request-name datum))
                 (define nth-service : (Option (Pairof Symbol SSH-Service-Constructor))
                   (and (not (hash-has-key? alive-services service))
                        (assq (ssh:msg:service:request-name datum) all-services)))
                 
                 (cond [(not nth-service) (ssh-log-message 'info (ssh-service-reject-description service))]
                       [else (let ([construct (cdr nth-service)])
                               (ssh-port-write sshd (make-ssh:msg:service:accept #:name service))
                               (hash-set! alive-services service (construct user session)))])])

          (read-dispatch-serve-loop))))

    (for ([service (in-hash-values alive-services)])
      (ssh-service.destruct service))
    
    (ssh-port-wait sshd #:abandon? #true)))
