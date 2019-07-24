#lang typed/racket/base

(provide (all-defined-out))
(provide ssh-stdin-evt make-ssh:msg:service:request)

(require "stdio.rkt")
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
   [appin : (SSH-Stdin Port)]
   [srvin : (SSH-Stdin Port)])
  #:type-name SSH-Session)

(define make-ssh-session : (-> SSH-Port (SSH-Nameof SSH-Application#) [#:applications (SSH-Name-Listof* SSH-Application#)] SSH-Session)
  (lambda [sshd 1st-λapplication #:applications [applications (ssh-registered-applications)]]
    (define-values (/dev/appin /dev/appout) (make-ssh-stdio (ssh-port-peer-name sshd)))
    (define-values (/dev/srvin /dev/srvout) (make-ssh-stdio (ssh-port-peer-name sshd)))
    
    (ssh-session sshd
                 (thread (λ [] (ssh-session-dispatch sshd /dev/appout /dev/srvout 1st-λapplication applications)))
                 /dev/appin /dev/srvin)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-dispatch : (-> SSH-Port (SSH-Stdout Port) (SSH-Stdout Port) (SSH-Nameof SSH-Application#) (SSH-Name-Listof* SSH-Application#) Void)
  (lambda [sshd /dev/appout /dev/srvout 1st-λapplication all-λapplications]
    (define sid : Bytes (ssh-port-session-identity sshd))
    (define rfc : SSH-Configuration (ssh-transport-preference sshd))
    (define 1st-app : SSH-Application ((cdr 1st-λapplication) (car 1st-λapplication) sid))
    (define alive-applications : (HashTable Symbol SSH-Application) (make-hasheq (list (cons (car 1st-λapplication) 1st-app))))

    (ssh-stdout-propagate /dev/srvout 1st-app)
    
    (with-handlers ([exn? (λ [[e : exn]] (ssh-shutdown sshd 'SSH-DISCONNECT-BY-APPLICATION (exn-message e)))])
      (letrec ([request-wait-dispatch-loop
                : (-> Void)
                (λ [] (apply sync/enable-break
                             (handle-evt (thread-receive-evt) (λ [e] (dispatch-guard-transmit (thread-receive))))
                             (handle-evt (ssh-port-datum-evt sshd) dispatch-filter-deliver)
                             (handle-evt (ssh-port-service-accept-evt sshd) setup-new-application)

                             (for/fold ([evts : (Listof (Evtof Void)) null])
                                       ([app (in-hash-values alive-applications)])
                               (define e : (Option (Evtof SSH-Service-Layer-Reply)) (ssh-application.data-evt app rfc))
                               
                               (cond [(not e) evts]
                                     [else (cons (handle-evt e (λ [[datum : SSH-Service-Layer-Reply]] (pipe-stream app datum)))
                                                 evts)]))))]

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
                                                     [(range) (ssh-application-range app)]
                                                     [(idmin idmax) (values (car range) (cdr range))])
                                         (cond [(not (<= idmin mid idmax)) (dispatch (cdr applications))]
                                               [else (ssh-send-messages sshd (ssh-application.transmit app datum rfc)
                                                                        /dev/appout idmin idmax (ssh-application-outgoing-log app))]))]))]

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
                                                       [(range) (ssh-application-range app)]
                                                       [(idmin idmax) (values (car range) (cdr range))])
                                           (cond [(not (<= idmin mid idmax)) (deliver (cdr applications))]
                                                 [else (ssh-send-messages sshd (ssh-application.deliver app datum rfc)
                                                                          /dev/appout idmin idmax (ssh-application-outgoing-log app))]))]))]
                          [else (ssh-port-ignore sshd datum)])

                    (request-wait-dispatch-loop))
        
                  (when (ssh:msg:disconnect? datum)
                    (ssh-log-message 'debug (ssh:msg:disconnect-description datum))))]

               [pipe-stream
                : (-> SSH-Application SSH-Service-Layer-Reply Void)
                (λ [app streams]
                  (let ([range (ssh-application-range app)])
                    (ssh-send-messages sshd streams /dev/appout (car range) (cdr range) (ssh-application-outgoing-log app)))

                  (request-wait-dispatch-loop))]

               [setup-new-application
                : (-> Symbol Void)
                (λ [name]
                  (define nth-λapp : (Option (Pairof Symbol SSH-Application-Constructor)) (assq name all-λapplications))

                  (unless (not nth-λapp)
                    (define nth-app : SSH-Application ((cdr nth-λapp) name sid))
                    
                    (hash-set! alive-applications name nth-app)
                    (ssh-stdout-propagate /dev/srvout nth-app))

                  (request-wait-dispatch-loop))])

        (request-wait-dispatch-loop)))
      
    (for ([application (in-hash-values alive-applications)])
      (ssh-application.destruct application))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-send-messages : (-> SSH-Port (U SSH-Service-Layer-Reply (Boxof Any)) (SSH-Stdout Port) Index Index (-> SSH-Message Void) Void)
  (lambda [sshc reply /dev/appout idmin idmax outgoing-log]
    (cond [(box? reply) (ssh-stdout-propagate /dev/appout (unbox reply))]
          [else (unless (not reply)
                  (for ([msg (if (list? reply) (in-list reply) (in-value reply))])
                    ; TODO: should be the transport layer messages allowed?
                    (if (<= idmin (ssh-message-number msg) idmax)
                        (void (outgoing-log msg)
                              (ssh-port-write sshc msg))
                        (ssh-port-ignore sshc msg))))])))
