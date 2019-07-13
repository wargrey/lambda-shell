#lang typed/racket/base

(provide (all-defined-out))

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
  [EXIT-STATUS    #:type 'exit-status    ([code : Index])]
  [EXIT-SIGNAL    #:type 'exit-signal    ([name #| without SIG |# : Symbol] [core? : Boolean] [error-message : String] [language : Symbol '||])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-session-channel ssh-channel
  ([cols : Index]
   [rows : Index]
   [width : Index]
   [height : Index]
   [modes : Bytes]

   [command : Path-String]
   [program : (Option Subprocess)]
   [outin : Input-Port]
   [errin : Input-Port]
   [stdout : Output-Port])
  #:type-name SSH-Session-Channel)

(define make-ssh-session-channel : SSH-Channel-Constructor
  (lambda [name msg rfc]
    (with-asserts ([msg ssh:msg:channel:open:session?])
      (ssh-session-channel (super-ssh-channel #:name name
                                              #:envariables (environment-variables-copy (current-environment-variables)) #:custodian (make-custodian)
                                              #:response ssh-session-response #:datum-evt ssh-session-datum-evt
                                              #:destruct ssh-session-destruct)
                           0 0 0 0 #""
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

             (cond [(null? command) (values self #false)]
                   [else (let ([program (find-executable-path (car command))])
                           (cond [(not program) (values self #false)]
                                 [else (ssh-session-exec self program (cdr command))]))])]

            [(ssh:msg:channel:request:shell? request)
             (parameterize ([current-environment-variables (ssh-channel-envariables self)]
                            [current-custodian (ssh-channel-custodian self)])
               (values self #false))]

            [(ssh:msg:channel:request:env? request)
             (define name : Bytes (ssh:msg:channel:request:env-name request))
             
             (values self
                     (and (member name ($ssh-allowed-envs rfc))
                          (ssh-session-putevn (ssh-channel-envariables self)
                                              (ssh:msg:channel:request:env-name request)
                                              (ssh:msg:channel:request:env-value request))))]

            [(ssh:msg:channel:request:pty:req? request)
             (define okay? : Boolean
               (ssh-session-putevn (ssh-channel-envariables self)
                                   #"TERM" (ssh:msg:channel:request:pty:req-TERM request)))

             (cond [(not okay?) (values self #false)]
                   [else (values (struct-copy ssh-session-channel self
                                              [modes (ssh:msg:channel:request:pty:req-modes request)]
                                              [cols (ssh:msg:channel:request:pty:req-cols request)] [rows (ssh:msg:channel:request:pty:req-rows request)]
                                              [width (ssh:msg:channel:request:pty:req-width request)] [height (ssh:msg:channel:request:pty:req-width request)])
                                 #true)])]
            
            [(ssh:msg:channel:request:window:change? request)
             (values (struct-copy ssh-session-channel self
                                  [cols (ssh:msg:channel:request:window:change-cols request)] [rows (ssh:msg:channel:request:window:change-rows request)]
                                  [width (ssh:msg:channel:request:window:change-width request)] [height (ssh:msg:channel:request:window:change-width request)])
                     #true)]

            [(ssh:msg:channel:request:exit:status? request)
             (ssh-log-message 'debug "remote program(~a) has terminated with exit code ~a"
                              (ssh-session-channel-command self)
                              (ssh:msg:channel:request:exit:status-code request))
             
             (values self #true)]
            
            [(ssh:msg:channel:request:exit:signal? request)
             (ssh-log-message 'debug "remote program(~a) has terminated due to signal SIG~a ~a core dumpped, details: ~a"
                              (ssh-session-channel-command self)
                              (ssh:msg:channel:request:exit:signal-name request)
                              (if (ssh:msg:channel:request:exit:signal-core? request) 'with 'without)
                              (ssh:msg:channel:request:exit:signal-error-message request))
             
             (values self #true)]
            
            [else (values self #false)]))))

(define ssh-session-datum-evt : SSH-Channel-Datum-Evt
  (lambda [self partner]
    (with-asserts ([self ssh-session-channel?])
      (define program : (Option Subprocess) (ssh-session-channel-program self))

      (and program
           (choice-evt (wrap-evt program (λ [[p : Subprocess]] (ssh-session-exit-status self program partner))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-session-putevn : (-> Environment-Variables Bytes Bytes Boolean)
  (lambda [evars name value]
    (define okay? : Boolean (and (environment-variables-set! evars name value (λ [] #false)) #true))
    
    (ssh-log-message 'debug "SET ~a=~a (~a)" name value (if (not okay?) 'failure 'success))
    okay?))

(define ssh-session-exec : (-> SSH-Session-Channel Path (Listof String) (Values SSH-Channel Boolean))
  (lambda [self program-path args]
    (cond [(ssh-session-channel-program self) (values self #false)]
          [else (parameterize ([subprocess-group-enabled #true]
                               [current-subprocess-custodian-mode 'kill]
                               [current-environment-variables (ssh-channel-envariables self)]
                               [current-custodian (ssh-channel-custodian self)])
                  (define-values (child /dev/outin /dev/stdout /dev/errin) (apply subprocess #false #false #false "program-path" args))

                  (ssh-log-message 'debug "exec ~a ~a" program-path (string-join args " "))
                  
                  (values (struct-copy ssh-session-channel self [command program-path]
                                       [program child] [outin /dev/outin] [stdout /dev/stdout] [errin /dev/errin])
                          #true))])))

(define ssh-session-exit-status : (-> SSH-Session-Channel Subprocess Index (Pairof SSH-Channel SSH-Channel-Reply))
  (lambda [self program partner]
    (define status (subprocess-status program))

    (ssh-log-message 'debug "program(~a) has terminated with exit code ~a" (ssh-session-channel-command self) status)

    (cond [(not (index? status)) (cons self #false)] ; still running, albeit this should not happen
          [else (cons (struct-copy ssh-session-channel self [program #false])
                      (list (make-ssh:msg:channel:request:exit:status #:recipient partner #:reply? #false #:code status)
                            (make-ssh:msg:channel:close #:recipient partner)))])))
