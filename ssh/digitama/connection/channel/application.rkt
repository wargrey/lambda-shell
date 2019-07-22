#lang typed/racket/base

(provide (all-defined-out))

(require racket/string)
(require racket/port)

(require "session.rkt")

(require "../channel.rkt")

(require "../../message.rkt")
(require "../../message/connection.rkt")

(require "../../stdio.rkt")
(require "../../diagnostics.rkt")

(require "../../../configuration.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-application-channel ssh-channel
  ([partner : Index]
   [program : (U String Symbol False)]

   ; for reading remote data
   [stdin : Input-Port]
   [usrout : Output-Port]

   ; for reading remote extended data
   [extin : (SSH-Stdin Port)]
   [extout : (SSH-Stdout Port)]

   ; for writing data and extended data
   [usrin : Input-Port]
   [stdout : Output-Port]

   ; for reading acknowledgements of local requests
   [ackin : (SSH-Stdin Port)]
   [ackout : (SSH-Stdout Port)])
  #:type-name SSH-Application-Channel
  #:mutable)

(define make-ssh-application-channel : SSH-Channel-Constructor
  (lambda [type id msg rfc]
    (parameterize ([current-custodian (make-custodian)])
      (define-values (stdin usrout) (make-pipe))
      (define-values (extin extout) (make-ssh-stdio 'ssh:msg:channel:extended:data))
      (define-values (usrin stdout) (make-pipe-with-specials))
      (define-values (ackin ackout) (make-ssh-stdio 'ssh:msg:channel:requst))
      
      (ssh-application-channel (super-ssh-channel #:type type #:name (make-ssh-channel-name type id) #:custodian (current-custodian)
                                                  #:response ssh-application-response #:notify ssh-application-notify
                                                  #:consume ssh-application-consume #:datum-evt ssh-application-datum-evt)
                               0 #false stdin usrout extin extout usrin stdout ackin ackout))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-application-notify : SSH-Channel-Notify
  (lambda [self msg rfc]
    (with-asserts ([self ssh-application-channel?])
      (cond [(ssh:msg:channel:open:confirmation? msg) (set-ssh-application-channel-partner! self (ssh:msg:channel:open:confirmation-sender msg))]
            [(ssh:msg:channel:success? msg) (ssh-stdout-propagate (ssh-application-channel-ackout self) #true)]
            [(ssh:msg:channel:failure? msg) (ssh-stdout-propagate (ssh-application-channel-ackout self) #false)]))))

(define ssh-application-response : SSH-Channel-Response
  (lambda [self request rfc]
    (with-asserts ([self ssh-application-channel?])
      (cond [(ssh:msg:channel:request:exit:status? request)
             (ssh-log-message 'debug "~a: remote program(~a) has terminated with exit code ~a" (ssh-channel-name self)
                              (ssh-application-channel-program self)
                              (ssh:msg:channel:request:exit:status-code request))
             #true]
            
            [(ssh:msg:channel:request:exit:signal? request)
             (ssh-log-message 'debug "~a: remote program(~a) has terminated due to signal SIG~a ~a core dumpped, details: ~a" (ssh-channel-name self)
                              (ssh-application-channel-program self)
                              (ssh:msg:channel:request:exit:signal-name request)
                              (if (ssh:msg:channel:request:exit:signal-core? request) 'with 'without)
                              (ssh:msg:channel:request:exit:signal-error-message request))
             #true]
            
            [else #false]))))

(define ssh-application-consume : SSH-Channel-Consume
  (case-lambda
    [(self octets partner)
     (with-asserts ([self ssh-application-channel?])
       (define /dev/usrout : Output-Port (ssh-application-channel-usrout self))

       (unless (port-closed? /dev/usrout)
         (cond [(eof-object? octets) (close-output-port /dev/usrout)]
               [else (void (write-bytes octets /dev/usrout)
                           (flush-output /dev/usrout))]))
       #false)]
    [(self octets type partner)
     (with-asserts ([self ssh-application-channel?])
       (ssh-stdout-propagate (ssh-application-channel-extout self)
                             (cons type octets))
       #false)]))

(define ssh-application-datum-evt : SSH-Channel-Datum-Evt
  (lambda [self parcel partner]
    (with-asserts ([self ssh-application-channel?])
      (define /dev/usrin : Input-Port (ssh-application-channel-usrin self))
      
      (and (not (port-closed? /dev/usrin))
           (wrap-evt /dev/usrin (λ [_] (ssh-user-read self /dev/usrin parcel partner)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-read : (-> SSH-Application-Channel Input-Port Bytes Index SSH-Channel-Reply)
  (lambda [self /dev/usrin parcel partner]
    (define hint : (U Natural EOF (-> (Option Positive-Integer) (Option Natural) (Option Positive-Integer) (Option Natural) Any))
      (read-bytes-avail! parcel /dev/usrin))

    (cond [(exact-nonnegative-integer? hint) (make-ssh:msg:channel:data #:recipient partner #:payload (subbytes parcel 0 hint))]
          [(eof-object? hint) (close-input-port /dev/usrin) (make-ssh:msg:channel:eof #:recipient partner)]
          [else (let ([data (hint #false #false #false #false)]
                      [upsize (bytes-length parcel)])
                  (cond [(ssh-message? data) (ssh-channel-filter self data partner upsize)]
                        [else (ssh-make-extended-data partner 'SSH-EXTENDED-DATA-STDERR
                                                (cond [(bytes? data) data]
                                                      [(string? data) (string->bytes/utf-8 data)]
                                                      [else (with-output-to-bytes (λ [] (write data)))])
                                                upsize)]))])))


(define ssh-channel-filter : (-> SSH-Application-Channel SSH-Message Index Index SSH-Channel-Reply)
  (lambda [self msg partner upsize]
    (cond [(ssh:msg:channel:request:shell? msg) (set-ssh-application-channel-program! self 'shell)]
          [(ssh:msg:channel:request:exec? msg) (set-ssh-application-channel-program! self (ssh:msg:channel:request:exec-command msg))]
          [(ssh:msg:channel:request:subsystem? msg) (set-ssh-application-channel-program! self (ssh:msg:channel:request:subsystem-name msg))])

    (cond [(ssh:msg:channel:request? msg) (and (= (ssh:msg:channel:request-recipient msg) partner) msg)]
          [(ssh:msg:channel:extended:data? msg) (and (= (ssh:msg:channel:extended:data-recipient msg) partner) (ssh-split-extended-data msg upsize))]
          [(ssh:msg:channel:data? msg) (and (= (ssh:msg:channel:data-recipient msg) partner) (ssh-split-data msg upsize))]
          [(ssh:msg:channel:close? msg) (and (= (ssh:msg:channel:close-recipient msg) partner) msg)]
          [else #false])))

(define ssh-split-data : (-> SSH-MSG-CHANNEL-DATA Index (U SSH-Message (Listof SSH-Message)))
  (lambda [msg upsize]
    (define payload : Bytes (ssh:msg:channel:data-payload msg))
    
    (cond [(<= (bytes-length payload) upsize) msg]
          [else (for/list : (Listof SSH-Message) ([data (in-list (ssh-split-bytes payload upsize))])
                  (make-ssh:msg:channel:data #:recipient (ssh:msg:channel:data-recipient msg) #:payload data))])))

(define ssh-split-extended-data : (-> SSH-MSG-CHANNEL-EXTENDED-DATA Index (U SSH-Message (Listof SSH-Message)))
  (lambda [msg upsize]
    (define payload : Bytes (ssh:msg:channel:extended:data-payload msg))

    (cond [(<= (bytes-length payload) upsize) msg]
          [else (for/list : (Listof SSH-Message) ([data (in-list (ssh-split-bytes payload upsize))])
                  (make-ssh:msg:channel:extended:data #:recipient (ssh:msg:channel:extended:data-recipient msg)
                                                      #:type (ssh:msg:channel:extended:data-type msg)
                                                      #:payload data))])))

(define ssh-split-bytes : (-> Bytes Index (Listof Bytes))
  (lambda [payload upsize]
    (define extsize : Index (bytes-length payload))

    (let split ([start : Nonnegative-Fixnum 0]
                [exts : (Listof Bytes) null])
      (cond [(>= start extsize) (reverse exts)]
            [else (split (+ start upsize)
                         (cons (subbytes payload start (+ start (min upsize (- extsize start))))
                               exts))]))))

(define ssh-make-extended-data : (-> Index Symbol Bytes Index (U SSH-Message (Listof SSH-Message)))
  (lambda [partner type payload upsize]
    (define extsize : Index (bytes-length payload))

    (cond [(<= extsize upsize) (make-ssh:msg:channel:extended:data #:recipient partner #:type type #:payload payload)]
          [else (for/list : (Listof SSH-Message) ([data (in-list (ssh-split-bytes payload upsize))])
                  (make-ssh:msg:channel:extended:data #:recipient partner #:type type #:payload data))])))
