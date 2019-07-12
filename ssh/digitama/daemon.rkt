#lang typed/racket/base

(provide (all-defined-out))

(require digimon/thread)

(require "../transport.rkt")
(require "../datatype.rkt")
(require "../configuration.rkt")

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
  (lambda [sshc user 1st-srv all-services]
    (define session : Bytes (ssh-port-session-identity sshc))
    (define rfc : SSH-Configuration (ssh-transport-preference sshc))
    (define-values (alive-services alive-evts)
      (let ([1st-service ((cdr 1st-srv) user session rfc)])
        (values (make-hasheq (list (cons (car 1st-srv) 1st-service)))
                (let ([empty-evt : (HashTable Symbol (Evtof (Pairof SSH-Service SSH-Message))) (make-hasheq)])
                  (ssh-datum-evts-set! empty-evt 1st-service)
                  empty-evt))))
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshc 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (exn-message e)))])
      (let read-dispatch-serve-loop ()
        (define datum : (U SSH-Datum (Pairof SSH-Service SSH-Message)) (apply sync/enable-break (ssh-port-datum-evt sshc) (hash-values alive-evts)))

        (unless (ssh-eof? datum)
          (cond [(bytes? datum)
                 (define mid : Byte (ssh-message-payload-number datum))
                 (let dispatch ([services (hash-values alive-services)])
                   (cond [(null? services) (ssh-port-write sshc (make-ssh:msg:unimplemented #:number mid))]
                         [else (let*-values ([(srv-state) (car services)]
                                             [(name) (ssh-service-name srv-state)]
                                             [(idmin idmax) (let ([r (ssh-service-range srv-state)]) (values (car r) (cdr r)))]
                                             [(log-outgoing-message) (ssh-service-log-outgoing srv-state)])
                                 (cond [(not (<= idmin mid idmax)) (dispatch (cdr services))]
                                       [else (let-values ([(srv++ response) (ssh-service.response srv-state datum)])
                                               (ssh-services-update! alive-services alive-evts srv++ srv-state)
                                               (unless (not response)
                                                 (for ([resp (if (list? response) (in-list response) (in-value response))])
                                                   (ssh-send-message sshc resp log-outgoing-message idmin idmax))))]))]))]
                
                [(ssh:msg:service:request? datum)
                 (define service : Symbol (ssh:msg:service:request-name datum))
                 (define nth-service : (Option (Pairof Symbol SSH-Service-Constructor))
                   (and (not (hash-has-key? alive-services service))
                        (assq (ssh:msg:service:request-name datum) all-services)))
                 
                 (cond [(not nth-service) (ssh-log-message 'info (ssh-service-reject-description service))]
                       [else (let ([construct (cdr nth-service)])
                               (ssh-port-write sshc (make-ssh:msg:service:accept #:name service))
                               (ssh-services-update! alive-services alive-evts (construct user session rfc) #false))])]

                [(pair? datum)
                 (define srv++ : SSH-Service (car datum))
                 (ssh-services-update! alive-services alive-evts srv++ (hash-ref alive-services (ssh-service-name srv++) (λ [] #false)))
                 (ssh-send-message sshc (cdr datum) srv++)]

                [else (ssh-port-write sshc (make-ssh:msg:unimplemented #:number (ssh-message-number datum)))])

          (read-dispatch-serve-loop))))

    (for ([service (in-hash-values alive-services)])
      (ssh-service.destruct service))
    
    (ssh-port-wait sshc #:abandon? #true)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-datum-evts-set! : (-> (HashTable Symbol (Evtof (Pairof SSH-Service SSH-Message))) SSH-Service Void)
  (lambda [evts srv]
    (define e (ssh-service.datum-evt srv))

    (unless (not e)
      (hash-set! evts (ssh-service-name srv) e))))

(define ssh-services-update! : (-> (HashTable Symbol SSH-Service) (HashTable Symbol (Evtof (Pairof SSH-Service SSH-Message))) SSH-Service (Option SSH-Service) Void)
  (lambda [alive-services alive-evts srv++ srv]
    (unless (eq? srv++ srv)
      (hash-set! alive-services (ssh-service-name srv++) srv++))

    (ssh-datum-evts-set! alive-evts srv++)))

(define ssh-send-message : (case-> [SSH-Port SSH-Message SSH-Service -> Void]
                                   [SSH-Port SSH-Message (-> SSH-Message Void) Index Index -> Void])
  (case-lambda
    [(sshc msg srv)
     (let ([range (ssh-service-range srv)])
       (ssh-send-message sshc msg (ssh-service-log-outgoing srv) (car range) (cdr range)))]
    [(sshc msg log-outgoing-message idmin idmax)
     (if (<= idmin (ssh-message-number msg) idmax)
         (void (log-outgoing-message msg)
               (ssh-port-write sshc msg))
         (ssh-port-ignore sshc msg))]))
