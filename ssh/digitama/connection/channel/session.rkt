#lang typed/racket/base

(provide (all-defined-out))
(provide environment-variables-copy)

(require racket/string)

(require "../channel.rkt")

(require "../../message.rkt")
(require "../../diagnostics.rkt")

(require "../../../configuration.rkt")

(require/typed racket/base
               [environment-variables-copy (-> Environment-Variables Environment-Variables)])

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require "../../message/connection.rkt")
(require (for-syntax "../../message/connection.rkt"))

(define-type SSH-Session-Signal  (U 'ABRT 'ALRM 'FPE 'HUP 'ILL 'INT 'KILL 'PIPE 'QUIT 'SEGV 'TERM 'USR1 'USR2))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-case-messages SSH-MSG-CHANNEL-OPEN
  ; https://tools.ietf.org/html/rfc4254#section-6.1
  [SESSION        #:type 'session        ()])

(define-ssh-case-messages SSH-MSG-CHANNEL-REQUEST
  ; https://tools.ietf.org/html/rfc4254#section-6.2
  [PTY-REQ        #:type 'pty-req        ([TERM : Bytes] [cols : Index] [rows : Index] [width : Index] [height : Index] [modes : Bytes])]
  ; https://tools.ietf.org/html/rfc4254#section-6.7
  [WINDOW-CHANGE  #:type 'window-change  ([cols : Index] [rows : Index] [width : Index] [height : Index])]
  ; https://tools.ietf.org/html/rfc4254#section-6.8
  [XON-XOFF       #:type 'xon-xoff       ([able? : Boolean])]
  
  ; https://tools.ietf.org/html/rfc4254#section-6.4
  [ENV            #:type 'env            ([name : Bytes] [value : Bytes])]

  ; https://tools.ietf.org/html/rfc4254#section-6.5
  [SHELL          #:type 'shell          ()]
  [EXEC           #:type 'exec           ([command : String])]
  [SUBSYSTEM      #:type 'subsystem      ([name : Symbol])]
  ; https://tools.ietf.org/html/rfc4254#section-6.9
  [SIGNAL         #:type 'signal         ([name #| without SIG |# : Symbol])]
  ; https://tools.ietf.org/html/rfc4254#section-6.10
  [EXIT-STATUS    #:type 'exit-status    ([code : Index])]
  [EXIT-SIGNAL    #:type 'exit-signal    ([name #| without SIG |# : Symbol] [core? : Boolean] [error-message : String] [language : Symbol '||])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-session-pty
  ([cols : Index]
   [rows : Index]
   [width : Index]
   [height : Index]
   [modes : Bytes])
  #:type-name SSH-Session-Pty
  #:transparent)

(struct ssh-session-channel ssh-channel
  ([envariables : Environment-Variables]
   [pty : SSH-Session-Pty]

   [command : Path-String]
   [program : (Option Subprocess)]
   [outin : Input-Port]
   [errin : Input-Port]
   [stdout : Output-Port])
  #:type-name SSH-Session-Channel
  #:mutable)

(define make-ssh-session-channel : SSH-Channel-Constructor
  (lambda [type id msg rfc]
    (with-asserts ([msg ssh:msg:channel:open:session?])
      (ssh-session-channel (super-ssh-channel #:type type #:name (make-ssh-channel-name type id) #:custodian (make-custodian)
                                              #:response ssh-session-response #:consume ssh-session-consume #:datum-evt ssh-session-datum-evt
                                              #:destruct ssh-session-destruct)
                           (environment-variables-copy (current-environment-variables)) (ssh-session-pty 0 0 0 0 #"")
                           "" #false (current-input-port) (current-input-port) (current-output-port)))))

(define ssh-session-destruct : SSH-Channel-Destructor
  (lambda [self]
    (with-asserts ([self ssh-session-channel?])
      (define program : (Option Subprocess) (ssh-session-channel-program self))

      (unless (not program)
        (subprocess-kill program #true)
        (subprocess-wait program))
      
      (ssh-channel-shutdown-custodian self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-response : SSH-Channel-Response
  (lambda [self request rfc]
    (with-asserts ([self ssh-session-channel?])
      (cond [(ssh:msg:channel:request:exec? request)
             (define command : (Listof String) (string-split (ssh:msg:channel:request:exec-command request)))

             (and (pair? command)
                  (let ([program (find-executable-path (car command))])
                    (and program (ssh-session-exec self program (cdr command)))))]

            [(ssh:msg:channel:request:shell? request)
             (parameterize ([current-environment-variables (ssh-session-channel-envariables self)]
                            [current-custodian (ssh-channel-custodian self)])
               #false)]

            [(ssh:msg:channel:request:env? request)
             (define name : Bytes (ssh:msg:channel:request:env-name request))
             
             (and (member name ($ssh-allowed-envs rfc))
                  (ssh-session-putevn (ssh-channel-name self) (ssh-session-channel-envariables self)
                                      (ssh:msg:channel:request:env-name request)
                                      (ssh:msg:channel:request:env-value request)))]

            [(ssh:msg:channel:request:pty:req? request)
             (and (ssh-session-putevn (ssh-channel-name self) (ssh-session-channel-envariables self)
                                      #"TERM" (ssh:msg:channel:request:pty:req-TERM request))
                  (let ([pty (struct-copy ssh-session-pty (ssh-session-channel-pty self)
                                          [modes (ssh:msg:channel:request:pty:req-modes request)]
                                          [cols (ssh:msg:channel:request:pty:req-cols request)] [rows (ssh:msg:channel:request:pty:req-rows request)]
                                          [width (ssh:msg:channel:request:pty:req-width request)] [height (ssh:msg:channel:request:pty:req-width request)])])
                    (set-ssh-session-channel-pty! self pty))
                  #true)]
            
            [(ssh:msg:channel:request:window:change? request)
             (define pty : SSH-Session-Pty
               (struct-copy ssh-session-pty (ssh-session-channel-pty self)
                            [cols (ssh:msg:channel:request:window:change-cols request)] [rows (ssh:msg:channel:request:window:change-rows request)]
                            [width (ssh:msg:channel:request:window:change-width request)] [height (ssh:msg:channel:request:window:change-width request)]))
             
             (set-ssh-session-channel-pty! self pty)
             #true]

            [(ssh:msg:channel:request:signal? request)
             (define program : (Option Subprocess) (ssh-session-channel-program self))
             (define signal : Symbol (ssh:msg:channel:request:signal-name request))
             (define kill? : Boolean (and (memq signal '(ABRT ILL FPE KILL PIPE SEGV)) #true))
             (define interrupt? : Boolean (and (memq signal '(INT QUIT TERM)) #true))

             (and program
                  (or kill? interrupt?)
                  (subprocess-kill program kill?)
                  #true)]
            
            [else #false]))))

(define ssh-session-consume : SSH-Channel-Consume
  (case-lambda
    [(self octets partner)
     (with-asserts ([self ssh-session-channel?])
       (define program : (Option Subprocess) (ssh-session-channel-program self))
         (define /dev/binout : Output-Port (ssh-session-channel-stdout self))

       (when (and program (not (port-closed? /dev/binout)))
         (cond [(eof-object? octets) (close-output-port /dev/binout)]
               [else (void (write-bytes octets /dev/binout)
                           (flush-output /dev/binout))]))
       #false)]
    [(self octets type partner)
     (with-asserts ([self ssh-session-channel?])
       (ssh-log-message 'error "~a: ~a" (make-ssh-channel-name 'channel partner) (string-trim (bytes->string/utf-8 octets)))
       #false)]))

(define ssh-session-datum-evt : SSH-Channel-Datum-Evt
  (lambda [self parcel partner]
    (with-asserts ([self ssh-session-channel?])
      (define program : (Option Subprocess) (ssh-session-channel-program self))
      (define outin : Input-Port (ssh-session-channel-outin self))
      (define errin : Input-Port (ssh-session-channel-errin self))

      (and program
           (let ([oievt (and (not (port-closed? outin)) (wrap-evt outin (λ [[oin : Input-Port]] (ssh-session-read self oin parcel #false partner errin))))]
                 [eievt (and (not (port-closed? errin)) (wrap-evt errin (λ [[ein : Input-Port]] (ssh-session-read self ein parcel 'STDERR partner outin))))]
                 [binevt (wrap-evt program (λ [[p : Subprocess]] (ssh-session-exit-status self program partner)))])
             (cond [(and oievt eievt) (choice-evt oievt eievt binevt)]
                   [(and oievt) (choice-evt oievt binevt)]
                   [(and eievt) (choice-evt eievt binevt)]
                   [else binevt]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-putevn : (-> Symbol Environment-Variables Bytes Bytes Boolean)
  (lambda [self-name evars name value]
    (define okay? : Boolean (and (environment-variables-set! evars name value (λ [] #false)) #true))
    
    (ssh-log-message 'debug "~a: SET ~a=~a (~a)" self-name
                     name value (if (not okay?) 'failure 'success))
    okay?))

(define ssh-session-exec : (-> SSH-Session-Channel Path (Listof String) Boolean)
  (lambda [self /usr/bin/program args]
    (and (not (ssh-session-channel-program self))
         (parameterize ([subprocess-group-enabled #true]
                        [current-subprocess-custodian-mode 'kill]
                        [current-environment-variables (ssh-session-channel-envariables self)]
                        [current-custodian (ssh-channel-custodian self)])
           (define-values (child /dev/outin /dev/stdout /dev/errin) (apply subprocess #false #false #false /usr/bin/program args))
           
           (ssh-log-message 'debug "~a: exec ~a ~a" (ssh-channel-name self) /usr/bin/program (string-join args " "))
           
           (set-ssh-session-channel-command! self /usr/bin/program)
           (set-ssh-session-channel-program! self child)
           (set-ssh-session-channel-outin! self /dev/outin)
           (set-ssh-session-channel-errin! self /dev/errin)
           (set-ssh-session-channel-stdout! self /dev/stdout)
           
           #true))))

(define ssh-session-read : (-> SSH-Session-Channel Input-Port Bytes (Option Symbol) Index Input-Port SSH-Channel-Reply)
  (lambda [self /dev/pin parcel ext-type partner other-in]
    (define size : (U Natural EOF Procedure) (read-bytes-avail! parcel /dev/pin))

    (cond [(exact-nonnegative-integer? size)
           (cond [(not ext-type) (make-ssh:msg:channel:data #:recipient partner #:payload (subbytes parcel 0 size))]
                 [else (let ([errmsg (subbytes parcel 0 size)])
                         (ssh-log-message 'error "~a: ~a" (ssh-channel-name self) (string-trim (bytes->string/utf-8 errmsg)))
                         (make-ssh:msg:channel:extended:data #:recipient partner #:payload errmsg #:type ext-type))])]
          [(eof-object? size)
           (close-input-port /dev/pin)
           (and (port-closed? other-in)
                (make-ssh:msg:channel:eof #:recipient partner))]
          [else #false])))

(define ssh-session-exit-status : (-> SSH-Session-Channel Subprocess Index SSH-Channel-Reply)
  (lambda [self program partner]
    (define status : (U Natural 'running) (subprocess-status program))

    (ssh-log-message 'debug "~a: program(~a) has terminated with exit code ~a"
                     (ssh-channel-name self) (ssh-session-channel-command self) status)

    (and (index? status)
         (set-ssh-session-channel-program! self #false)
         (list (make-ssh:msg:channel:request:exit:status #:recipient partner #:reply? #false #:code status)
               (make-ssh:msg:channel:close #:recipient partner)))))
