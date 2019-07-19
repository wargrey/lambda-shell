#lang typed/racket/base

(provide (all-defined-out))

(require "service.rkt")
(require "message.rkt")
(require "assignment.rkt")
(require "transport.rkt")
(require "diagnostics.rkt")

(require "../transport.rkt")
(require "../datatype.rkt")
(require "../configuration.rkt")

(require "message/transport.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-session
  ([port : SSH-Port]
   [ghostcat : Thread]
   [applications : (HashTable Symbol SSH-Application)])
  #:type-name SSH-Session)

(define make-ssh-session : (-> SSH-Port (SSH-Nameof SSH-Application#) [#:applications (SSH-Name-Listof* SSH-Application#)] SSH-Session)
  (lambda [sshd 1st-λapplication #:applications [applications (ssh-registered-applications)]]
    (define alive-applications : (HashTable Symbol SSH-Application)
      (make-hasheq (list (cons (car 1st-λapplication)
                               ((cdr 1st-λapplication) (car 1st-λapplication)
                                                       (ssh-port-session-identity sshd))))))
    
    (ssh-session sshd
                 (thread (λ [] (ssh-session-dispatch sshd alive-applications applications)))
                 alive-applications)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-dispatch : (-> SSH-Port (HashTable Symbol SSH-Application) (SSH-Name-Listof* SSH-Application#) Void)
  (lambda [sshd alive-applications all-λapplications]
    (define sid : Bytes (ssh-port-session-identity sshd))
    (define rfc : SSH-Configuration (ssh-transport-preference sshd))
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
      (letrec ([request-wait-dispatch-loop
                : (-> Void)
                (λ [] (sync/enable-break (handle-evt (thread-receive-evt) (λ [e] (dispatch-guard-transmit (thread-receive))))
                                         (handle-evt (ssh-port-datum-evt sshd) dispatch-filter-deliver)))]

               [dispatch-guard-transmit
                : (-> Any Void)
                (λ [[datum : Any]]
                  (cond [(ssh:msg:service:request? datum)
                         (define name : Symbol (ssh:msg:service:request-name datum))
                         (define nth-application : (Option (Pairof Symbol SSH-Application-Constructor))
                           (and (not (hash-has-key? alive-applications name))
                                (assq name all-λapplications)))
                         
                         (cond [(not nth-application) (ssh-log-message 'warning (ssh-service-not-configured-description name))]
                               [else (ssh-port-write sshd datum)])]
                        
                        [(ssh-message? datum)
                         (define mid : Byte (ssh-message-number datum))
                         (let dispatch ([applications (hash-values alive-applications)])
                           (cond [(null? applications) (ssh-port-ignore sshd mid)]
                                 [else (let*-values ([(app) (car applications)]
                                                     [(idmin idmax) (let ([r (ssh-application-range app)]) (values (car r) (cdr r)))]
                                                     [(log-outgoing-message) (ssh-application-log-outgoing app)])
                                         (cond [(not (<= idmin mid idmax)) (dispatch (cdr applications))]
                                               [else (let ([requests (ssh-application.guard app datum rfc)])
                                                       (unless (not requests)
                                                         (for ([req (if (list? requests) (in-list requests) (in-value requests))])
                                                           (ssh-send-message sshd req log-outgoing-message idmin idmax))))]))]))]

                        [else (ssh-port-write sshd datum)])
                  
                  (request-wait-dispatch-loop))]

               [dispatch-filter-deliver
                : (-> SSH-Datum Void)
                (λ [datum]
                  (unless (ssh-eof? datum)
                    (cond [(bytes? datum)
                           (define mid : Byte (ssh-message-payload-number datum))
                           (let deliver ([applications (hash-values alive-applications)])
                             (cond [(null? applications) (ssh-port-ignore sshd datum)]
                                   [else (let*-values ([(app) (car applications)]
                                                       [(idmin idmax) (let ([r (ssh-application-range app)]) (values (car r) (cdr r)))]
                                                       [(log-outgoing-message) (ssh-application-log-outgoing app)])
                                           (cond [(not (<= idmin mid idmax)) (deliver (cdr applications))]
                                                 [else (let ([responses (ssh-application.deliver app datum rfc)])
                                                         (unless (not responses)
                                                           (for ([resp (if (list? responses) (in-list responses) (in-value responses))])
                                                             (ssh-send-message sshd resp log-outgoing-message idmin idmax))))]))]))]
                          
                          [(ssh:msg:service:accept? datum)
                           (define name : Symbol (ssh:msg:service:accept-name datum))
                           (define nth-app : (Option (Pairof Symbol SSH-Application-Constructor)) (assq name all-λapplications))

                           (unless (not nth-app)
                             (hash-set! alive-applications name ((cdr nth-app) name sid)))]
                          
                          [else (ssh-port-ignore sshd datum)])

                    (request-wait-dispatch-loop))
        
                  (when (ssh:msg:disconnect? datum)
                    (ssh-log-message 'debug (ssh:msg:disconnect-description datum))))])

        (request-wait-dispatch-loop)))
      
    (for ([application (in-hash-values alive-applications)])
      (ssh-application.destruct application))

    (ssh-log-message 'debug "bye!")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#;(define ssh-datum-evts : (-> (HashTable Symbol SSH-Application) SSH-Configuration (Listof (Evtof (Pairof SSH-Application SSH-Service-Layer-Reply))))
  (lambda [services rfc]
    (let filter-map ([services : (Listof SSH-Application) (hash-values services)]
                     [evts : (Listof (Evtof (Pairof SSH-Application SSH-Service-Layer-Reply))) null])
      (cond [(null? services) evts]
            [else (let ([e (ssh-application.datum-evt (car services) rfc)])
                    (cond [(not e) (filter-map (cdr services) evts)]
                          [else (filter-map (cdr services) (cons e evts))]))]))))

(define ssh-send-message : (-> SSH-Port SSH-Message (-> SSH-Message Void) Index Index Void)
  (lambda [sshc msg log-outgoing-message idmin idmax]
    ; TODO: should be the transport layer messages allowed?
    (if (<= idmin (ssh-message-number msg) idmax)
        (void (log-outgoing-message msg)
              (ssh-port-write sshc msg))
        (ssh-port-ignore sshc msg))))
