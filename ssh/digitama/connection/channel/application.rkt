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

(require typed/racket/unsafe)

(require/typed
 racket/base
 [make-pipe (->* () ((Option Positive-Integer) Any Any) (Values Input-Port Output-Port))])

(unsafe-require/typed
 racket/base
 [(wrap-evt log-evt) (All (a b) (-> Log-Receiver (-> (Immutable-Vector Log-Level String a (Option Symbol)) b) (Evtof b)))])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-application-channel ssh-channel
  ([partner : Index]
   [sshout : Logger]
   [program : (U String Symbol False)]
   [done : Semaphore]

   ; reading data
   [stdin : Input-Port]
   [usrout : Output-Port]

   ; writing data
   [usrin : Input-Port]
   [stdout : Output-Port]

   ; reading extended data
   [extin : Log-Receiver]
   ; writing messages (including extended data)
   [msgin : Log-Receiver]
   ; reading acknowledgements of local requests
   [ackin : Log-Receiver]
   ; reading acknowledgements of local requests
   [retin : Log-Receiver])
  #:type-name SSH-Application-Channel
  #:mutable)

(define make-ssh-application-channel : SSH-Channel-Constructor
  (lambda [type id msg rfc]
    (parameterize ([current-custodian (make-custodian)])
      (define name : Symbol (make-ssh-channel-name type id))
      (define sshout : Logger (make-logger name #false))
      (define-values (stdin usrout) (make-pipe #false name name))
      (define-values (usrin stdout) (make-pipe #false name name))
      (define extin : Log-Receiver (make-log-receiver sshout 'debug 'extended:data))
      (define msgin : Log-Receiver (make-log-receiver sshout 'debug 'ssh:msg:channel))
      (define ackin : Log-Receiver (make-log-receiver sshout 'debug 'request:reply))
      (define retin : Log-Receiver (make-log-receiver sshout 'debug 'exit:status))
      
      (ssh-application-channel (super-ssh-channel #:type type #:name name #:custodian (current-custodian)
                                                  #:response ssh-application-response #:notify ssh-application-notify
                                                  #:consume ssh-application-consume #:datum-evt ssh-application-datum-evt
                                                  #:destruct ssh-application-channel-destruct)
                               0 sshout #false (make-semaphore 0) stdin usrout usrin stdout extin msgin ackin retin))))

(define ssh-application-channel-destruct : SSH-Channel-Destructor
  (lambda [self]
    (with-asserts ([self ssh-application-channel?])
      (semaphore-post (ssh-application-channel-done self))
      (ssh-channel-shutdown-custodian self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-application-notify : SSH-Channel-Notify
  (lambda [self msg rfc]
    (with-asserts ([self ssh-application-channel?])
      (cond [(ssh:msg:channel:open:confirmation? msg) (set-ssh-application-channel-partner! self (ssh:msg:channel:open:confirmation-sender msg))]
            [(ssh:msg:channel:success? msg) (ssh-chout-propagate (ssh-application-channel-sshout self) #true #:topic 'request:reply)]
            [(ssh:msg:channel:failure? msg) (ssh-chout-propagate (ssh-application-channel-sshout self) #false #:topic 'request:reply)]))))

(define ssh-application-response : SSH-Channel-Response
  (lambda [self request rfc]
    (with-asserts ([self ssh-application-channel?])
      (cond [(ssh:msg:channel:request:exit:status? request)
             (define retcode : Index (ssh:msg:channel:request:exit:status-code request))
             (ssh-log-message (if (zero? retcode) 'debug 'error)
                              "~a: remote program(~a) has terminated with exit code ~a" (ssh-channel-name self)
                              (ssh-application-channel-program self) retcode)
             (ssh-chout-propagate (ssh-application-channel-sshout self) retcode #:topic 'exit:status)]
            
            [(ssh:msg:channel:request:exit:signal? request)
             (ssh-log-message 'warning "~a: remote program(~a) has terminated due to signal SIG~a ~a core dumpped, details: ~a" (ssh-channel-name self)
                              (ssh-application-channel-program self)
                              (ssh:msg:channel:request:exit:signal-name request)
                              (if (ssh:msg:channel:request:exit:signal-core? request) 'with 'without)
                              (ssh:msg:channel:request:exit:signal-error-message request))])

      #false)))

(define ssh-application-consume : SSH-Channel-Consume
  (case-lambda
    [(self octets partner)
     (with-asserts ([self ssh-application-channel?])
       (define /dev/usrout : Output-Port (ssh-application-channel-usrout self))

       (unless (port-closed? /dev/usrout)
         (cond [(eof-object? octets) (close-output-port /dev/usrout)]
               [else (void (write-bytes octets /dev/usrout)
                           (flush-output /dev/usrout))])))]
    [(self octets type partner)
     (with-asserts ([self ssh-application-channel?])
       (define description : String (string-trim (bytes->string/utf-8 octets)))
       
       (ssh-log-extended-data (ssh-channel-name self) type description)
       (ssh-chout-propagate (ssh-application-channel-sshout self) (cons type description) #:topic 'extended:data))]))

(define ssh-application-datum-evt : SSH-Channel-Datum-Evt
  (lambda [self parcel partner window]
    (with-asserts ([self ssh-application-channel?])
      (define program : (Option (U String Symbol)) (ssh-application-channel-program self))
      (define /dev/usrin : Input-Port (ssh-application-channel-usrin self))
      (define /dev/msgin : (SSH-Stdin Port) (ssh-application-channel-msgin self))
      (define upsize : Index (bytes-length parcel))
      
      (define maybe-usrin-evt : (Option (Evtof SSH-Channel-Reply))
        (and program
             (< upsize window)
             (not (port-closed? /dev/usrin))
             (wrap-evt /dev/usrin (λ [_] (ssh-user-read self /dev/usrin parcel partner)))))

      (define maybe-msgin-evt : (Option (Evtof SSH-Channel-Reply))
        (and (not (port-closed? /dev/usrin))
             ((inst ssh-chin-evt (U SSH-Message (Listof SSH-Message)) SSH-Channel-Reply)
              /dev/msgin
              (λ [[msg : (U SSH-Message (Listof SSH-Message))]]
                (cond [(list? msg) (ssh-channel-filter* self msg partner upsize)]
                      [else (ssh-channel-filter self msg partner upsize)])))))

      (cond [(and maybe-usrin-evt maybe-msgin-evt) (choice-evt maybe-usrin-evt maybe-msgin-evt)]
            [else (or maybe-usrin-evt maybe-msgin-evt (void))]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-user-read : (-> SSH-Application-Channel Input-Port Bytes Index SSH-Channel-Reply)
  (lambda [self /dev/usrin parcel partner]
    ;; NOTE
    ; It seems that special pipes dislike bytes
    ; If large amount of bytes are written to the special pipe continuously
    ;   the readers have a high probability to see byte one by one for each continuation
    ; Normal pipes have no such problems
    
    (define size : (U Natural EOF Procedure) (read-bytes-avail! parcel /dev/usrin))

    (cond [(exact-nonnegative-integer? size) (make-ssh:msg:channel:data #:recipient partner #:payload (subbytes parcel 0 size))]
          [else (close-input-port /dev/usrin) (make-ssh:msg:channel:eof #:recipient partner)])))

(define ssh-channel-filter : (-> SSH-Application-Channel (U SSH-Message (Listof SSH-Message)) Index Index SSH-Channel-Reply)
  (lambda [self msg partner upsize]
    (cond [(ssh:msg:channel:request:shell? msg) (set-ssh-application-channel-program! self 'shell)]
          [(ssh:msg:channel:request:exec? msg) (set-ssh-application-channel-program! self (ssh:msg:channel:request:exec-command msg))]
          [(ssh:msg:channel:request:subsystem? msg) (set-ssh-application-channel-program! self (ssh:msg:channel:request:subsystem-name msg))])

    (cond [(ssh:msg:channel:request? msg) (when (= (ssh:msg:channel:request-recipient msg) partner) msg)]
          [(ssh:msg:channel:extended:data? msg) (when (= (ssh:msg:channel:extended:data-recipient msg) partner) (ssh-split-extended-data msg upsize))]
          [(ssh:msg:channel:data? msg) (when (= (ssh:msg:channel:data-recipient msg) partner) (ssh-split-data msg upsize))]
          [(ssh:msg:channel:close? msg) (when (= (ssh:msg:channel:close-recipient msg) partner) msg)])))

(define ssh-channel-filter* : (-> SSH-Application-Channel (Listof SSH-Message) Index Index SSH-Channel-Reply)
  (lambda [self msgs partner upsize]
    (let filter ([replies : (Listof SSH-Message) null]
                 [rest : (Listof SSH-Message) msgs])
      (cond [(null? rest) (when (pair? replies) replies)]
            [else (let ([msg (ssh-channel-filter self (car rest) partner upsize)])
                    (cond [(void? msg) (filter replies (cdr rest))]
                          [(list? msg) (filter (append replies msg) (cdr rest))]
                          [else (filter (append replies (list msg)) (cdr rest))]))]))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-chin-evt : (All (a b) (case-> [Log-Receiver (-> a b) -> (Evtof b)]
                                          [Log-Receiver -> (Evtof a)]))
  (case-lambda
    [(/dev/sshin)
     ((inst log-evt a a) /dev/sshin
                         (λ [[info : (Immutable-Vector Log-Level String a (Option Symbol))]]
                           (vector-ref info 2)))]
    [(/dev/sshin wrap)
     ((inst log-evt a b) /dev/sshin
                         (λ [[info : (Immutable-Vector Log-Level String a (Option Symbol))]]
                           (wrap (vector-ref info 2))))]))

(define ssh-chout-propagate : (->* ((SSH-Stdout Port) Any #:topic Symbol) (String #:level Log-Level) Void)
  (lambda [/dev/sshout msg [description ""] #:topic topic #:level [level 'debug]]
    (log-message /dev/sshout level topic description msg)))
