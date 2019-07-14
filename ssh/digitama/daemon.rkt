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
                               ((cdr 1st-λservice) (car 1st-λservice) user session rfc)))))
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshc 'SSH-DISCONNECT-AUTH-CANCELLED-BY-USER (exn-message e)))])
      (let read-dispatch-serve-loop ()
        (define datum : (U SSH-Datum (Pairof SSH-Service SSH-Service-Reply))
          (apply sync/enable-break (ssh-port-datum-evt sshc)
                 (ssh-datum-evts alive-services)))

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
                                       [else (let-values ([(srv++ responses) (ssh-service.response srv-state datum)])
                                               (ssh-services-update! alive-services srv++ srv-state)
                                               (unless (not responses)
                                                 (for ([resp (if (list? responses) (in-list responses) (in-value responses))])
                                                   (ssh-send-message sshc resp log-outgoing-message idmin idmax))))]))]))]
                
                [(ssh:msg:service:request? datum)
                 (define service : Symbol (ssh:msg:service:request-name datum))
                 (define nth-service : (Option (Pairof Symbol SSH-Service-Constructor))
                   (and (not (hash-has-key? alive-services service))
                        (assq (ssh:msg:service:request-name datum) all-λservices)))
                 
                 (cond [(not nth-service) (ssh-log-message 'info (ssh-service-reject-description service))]
                       [else (let ([construct (cdr nth-service)])
                               (ssh-port-write sshc (make-ssh:msg:service:accept #:name service))
                               (ssh-services-update! alive-services (construct (car nth-service) user session rfc) #false))])]

                [(pair? datum)
                 (define srv++ : SSH-Service (car datum))
                 (define feedbacks : SSH-Service-Reply (cdr datum))
                 
                 (ssh-services-update! alive-services srv++ (hash-ref alive-services (ssh-service-name srv++) (λ [] #false)))

                 (unless (not feedbacks)
                   (let-values ([(idmin idmax) (let ([r (ssh-service-range srv++)]) (values (car r) (cdr r)))]
                                [(log-outgoing-message) (ssh-service-log-outgoing srv++)])
                     (for ([resp (if (list? feedbacks) (in-list feedbacks) (in-value feedbacks))])
                       (ssh-send-message sshc resp log-outgoing-message idmin idmax))))]

                [else (ssh-port-write sshc (make-ssh:msg:unimplemented #:number (ssh-message-number datum)))])

          (read-dispatch-serve-loop))))

    (for ([service (in-hash-values alive-services)])
      (ssh-service.destruct service))

    (ssh-port-wait sshc #:abandon? #true)
    (ssh-log-message 'debug "Good Bye!")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-datum-evts : (-> (HashTable Symbol SSH-Service) (Listof (Evtof (Pairof SSH-Service SSH-Service-Reply))))
  (lambda [services]
    (let filter-map ([services : (Listof SSH-Service) (hash-values services)]
                     [evts : (Listof (Evtof (Pairof SSH-Service SSH-Service-Reply))) null])
      (cond [(null? services) evts]
            [else (let ([e (ssh-service.datum-evt (car services))])
                    (cond [(not e) (filter-map (cdr services) evts)]
                          [else (filter-map (cdr services) (cons e evts))]))]))))

(define ssh-services-update! : (-> (HashTable Symbol SSH-Service) SSH-Service (Option SSH-Service) Void)
  (lambda [alive-services srv++ srv]
    (unless (eq? srv++ srv)
      (hash-set! alive-services (ssh-service-name srv++) srv++))))

(define ssh-send-message : (-> SSH-Port SSH-Message (-> SSH-Message Void) Index Index Void)
  (lambda [sshc msg log-outgoing-message idmin idmax]
    ; TODO: should be the transport layer messages allowed?
    (if (<= idmin (ssh-message-number msg) idmax)
        (void (log-outgoing-message msg)
              (ssh-port-write sshc msg))
        (ssh-port-ignore sshc msg))))
