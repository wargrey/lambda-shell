#lang typed/racket/base

(provide (all-defined-out))

(require "../channel.rkt")

(require "../../message.rkt")
(require "../../message/connection.rkt")
(require "../../diagnostics.rkt")

(require "../../../datatype.rkt")
(require "../../../configuration.rkt")

(require/typed racket/base
               [environment-variables-copy (-> Environment-Variables Environment-Variables)])

; `define-ssh-case-messages` requires this because of Racket's phase isolated compilation model
(require (for-syntax "../../message/connection.rkt"))

(define ssh-session-signals : (Listof Symbol)
  '(ABRT ALRM FPE HUP ILL INT KILL PIPE QUIT SEGV TERM USR1 USR2))

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
  [SUBSYSTEM      #:type 'subsystem      ([name : Symbol]) #:case name]
  ; https://tools.ietf.org/html/rfc4254#section-6.9
  [SIGNAL         #:type 'signal         ([name #| without SIG |# : Symbol])]
  ; https://tools.ietf.org/html/rfc4254#section-6.10
  [EXIT-STATUS    #:type 'exit-status    ([retcode : Index])]
  [EXIT-SIGNAL    #:type 'exit-signal    ([name #| without SIG |# : Symbol] [core? : Boolean] [errmsg : String] [language : Symbol '||])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-session-channel ssh-channel
  ([cols : Index]
   [rows : Index]
   [width : Index]
   [height : Index]
   [modes : Bytes])
  #:type-name SSH-Session-Channel)

(define make-ssh-session-channel : SSH-Channel-Constructor
  (lambda [name msg rfc]
    (with-asserts ([msg ssh:msg:channel:open:session?])
      (ssh-session-channel (super-ssh-channel #:name name
                                              #:envariables (environment-variables-copy (current-environment-variables)) #:custodian (make-custodian)
                                              #:response ssh-session-channel-response)
                           0 0 0 0 #""))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-channel-response : SSH-Channel-Response
  (lambda [self request partner-id reply? rfc]
    (with-asserts ([self ssh-session-channel?])
      (cond [(ssh:msg:channel:request:shell? request)
             (parameterize ([current-environment-variables (ssh-channel-envariables self)])
               (values self (and reply? (make-ssh:msg:channel:failure #:recipient partner-id))))]

            [(ssh:msg:channel:request:env? request)
             (define name : Bytes (ssh:msg:channel:request:env-name request))
             (define okay? : Boolean
               (and (member name ($ssh-allowed-envs rfc))
                    (ssh-session-putevn (ssh-channel-envariables self)
                                        (ssh:msg:channel:request:env-name request)
                                        (ssh:msg:channel:request:env-value request))))

             (values self
                     (and reply?
                          (if (not okay?)
                              (make-ssh:msg:channel:success #:recipient partner-id)
                              (make-ssh:msg:channel:failure #:recipient partner-id))))]

            [(ssh:msg:channel:request:pty:req? request)
             (define okay? : Boolean
               (ssh-session-putevn (ssh-channel-envariables self)
                                   #"TERM" (ssh:msg:channel:request:pty:req-TERM request)))

             (cond [(not okay?) (values self (make-ssh:msg:channel:failure #:recipient partner-id))]
                   [else (values (struct-copy ssh-session-channel self
                                              [modes (ssh:msg:channel:request:pty:req-modes request)]
                                              [cols (ssh:msg:channel:request:pty:req-cols request)] [rows (ssh:msg:channel:request:pty:req-rows request)]
                                              [width (ssh:msg:channel:request:pty:req-width request)] [height (ssh:msg:channel:request:pty:req-width request)])
                                 (and reply? (make-ssh:msg:channel:success #:recipient partner-id)))])]
            
            [(ssh:msg:channel:request:window:change? request)
             (values (struct-copy ssh-session-channel self
                                  [cols (ssh:msg:channel:request:window:change-cols request)] [rows (ssh:msg:channel:request:window:change-rows request)]
                                  [width (ssh:msg:channel:request:window:change-width request)] [height (ssh:msg:channel:request:window:change-width request)])
                     (and reply? (make-ssh:msg:channel:success #:recipient partner-id)))]
            
            [else (values self #false)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-putevn : (-> Environment-Variables Bytes Bytes Boolean)
  (lambda [evars name value]
    (define okay? : Boolean (and (environment-variables-set! evars name value (λ [] #false)) #true))
    
    (ssh-log-message 'debug "SET ~a=~a (~a)" name value (if (not okay?) 'failure 'success))
    okay?))
