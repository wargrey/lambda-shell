#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "service.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "transport.rkt")
(require "diagnostics.rkt")

(require "../transport.rkt")
(require "../datatype.rkt")
(require "../configuration.rkt")

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

    (define root-custodian : Custodian (ssh-custodian sshd))
    (parameterize ([current-custodian (make-custodian root-custodian)])
      (with-handlers ([exn:break? void])
        (let sync-accept-serve-loop ()
          (sync/enable-break (ssh-listener-evt sshd))
          (thread ssh-port-accept)
          
          (sync-accept-serve-loop)))

      (thread-safe-shutdown (current-custodian) root-custodian)
      (ssh-shutdown sshd))))

(define ssh-daemon-dispatch : (-> SSH-Port SSH-User (SSH-Nameof SSH-Service#) (SSH-Name-Listof* SSH-Service#) Void)
  (lambda [sshc user 1st-λservice all-λservices]
    (define session : Bytes (ssh-port-session-identity sshc))
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define alive-services : (HashTable Symbol SSH-Service)
      (make-hasheq (list (cons (car 1st-λservice)
                               ((cdr 1st-λservice) (car 1st-λservice) user session)))))
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshc 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
      (letrec ([sync-dispatch-response-feedback-loop
                : (-> Void)
                (λ []
                  (apply sync/enable-break
                         (handle-evt (ssh-port-datum-evt sshc) dispatch-response)

                         (for/fold ([evts : (Listof (Evtof Void)) null])
                                   ([service (in-hash-values alive-services)])
                           (define e : (Option (Evtof SSH-Service-Layer-Reply)) (ssh-service.push-evt service rfc))

                           (cond [(not e) evts]
                                 [else (cons (handle-evt e (λ [[datum : SSH-Service-Layer-Reply]] (pushback service datum)))
                                             evts)]))))]

               [dispatch-response
                : (-> SSH-Datum Void)
                (λ [datum]
                  (unless (ssh-eof? datum)
                    (cond [(bytes? datum)
                           (define mid : Byte (ssh-message-payload-number datum))
                           (let dispatch ([services (hash-values alive-services)])
                             (cond [(null? services) (ssh-port-write sshc (make-ssh:msg:unimplemented #:number mid))]
                                   [else (let*-values ([(service) (car services)]
                                                       [(idmin idmax) (let ([r (ssh-service-range service)]) (values (car r) (cdr r)))])
                                           (cond [(not (<= idmin mid idmax)) (dispatch (cdr services))]
                                                 [else (let ([responses (ssh-service.response service datum rfc)])
                                                         (unless (not responses)
                                                           (for ([resp (if (list? responses) (in-list responses) (in-value responses))])
                                                             (ssh-send-message sshc resp idmin idmax))))]))]))]
                          
                          [(ssh:msg:service:request? datum)
                           (define name : Symbol (ssh:msg:service:request-name datum))
                           (define nth-service : (Option (Pairof Symbol SSH-Service-Constructor))
                             (and (not (hash-has-key? alive-services name))
                                  (assq name all-λservices)))
                           
                           (cond [(not nth-service) (ssh-log-message 'info (ssh-service-reject-description name))]
                                 [else (let ([construct (cdr nth-service)])
                                         (ssh-port-write sshc (make-ssh:msg:service:accept #:name name))
                                         (hash-set! alive-services name (construct name user session)))])]
                          
                          [else (ssh-port-write sshc (make-ssh:msg:unimplemented #:number (ssh-message-number datum)))])

                    (sync-dispatch-response-feedback-loop))

                  (when (ssh:msg:disconnect? datum)
                    (ssh-log-message 'debug (ssh:msg:disconnect-description datum))))]

               [pushback
                : (-> SSH-Service SSH-Service-Layer-Reply Void)
                (λ [srv requests]
                  (unless (not requests)
                    (let-values ([(idmin idmax) (let ([r (ssh-service-range srv)]) (values (car r) (cdr r)))])
                      (for ([resp (if (list? requests) (in-list requests) (in-value requests))])
                        (ssh-send-message sshc resp idmin idmax))))

                  (sync-dispatch-response-feedback-loop))])
        
        (sync-dispatch-response-feedback-loop)))

    (for ([service (in-hash-values alive-services)])
      (ssh-service.destruct service))

    (ssh-port-wait sshc #:abandon? #true)
    (ssh-log-message 'debug "bye")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-send-message : (-> SSH-Port SSH-Message Index Index Void)
  (lambda [sshc msg idmin idmax]
    ; TODO: should be the transport layer messages allowed?
    (if (<= idmin (ssh-message-number msg) idmax)
        (ssh-port-write sshc msg)
        (ssh-port-ignore sshc msg))))
