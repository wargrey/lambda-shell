#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4252

(provide (all-defined-out) SSH-Connection-Application SSH-Application-Channel SSH-Session-Signal)
(provide ssh-connection-application? ssh-application-channel?)
(provide (all-from-out "digitama/message/connection.rkt"))

(require "digitama/stdio.rkt")
(require "digitama/connection/chid.rkt")
(require "digitama/connection/application.rkt")
(require "digitama/connection/channel/session.rkt")
(require "digitama/connection/channel/application.rkt")

(require "digitama/message/connection.rkt")

;; register builtin assignments for services and applications
(require "digitama/assignment/service.rkt")
(require "digitama/assignment/application.rkt")

;; register builtin assignments for channels
(require "digitama/assignment/channel.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-connection-open-channel-message : (-> SSH-Connection-Application Symbol #:window-size Index #:packet-capacity Index [#:make-channel-id (Option (-> Index))]
                                                  SSH-MSG-CHANNEL-OPEN)
  (lambda [self channel-type #:window-size window #:packet-capacity capacity #:make-channel-id [make-id #false]]
    (define id : Index (make-ssh-channel-uuid (or make-id make-ssh-channel-id) (ssh-connection-application-ports self)))

    (make-ssh:msg:channel:open #:type channel-type #:sender id
                               #:window-size window #:packet-capacity capacity)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-remote-id : (-> SSH-Application-Channel Index)
  (lambda [self]
    (ssh-application-channel-partner self)))

(define ssh-channel-program : (-> SSH-Application-Channel (U String Symbol False))
  (lambda [self]
    (ssh-application-channel-program self)))

(define ssh-channel-stdio-port : (-> SSH-Application-Channel (Values Input-Port Output-Port))
  (lambda [self]
    (values (ssh-application-channel-stdin self)
            (ssh-application-channel-stdout self))))

(define ssh-channel-data-evt : (-> SSH-Application-Channel (Evtof Input-Port))
  (lambda [self]
    (ssh-application-channel-stdin self)))

(define ssh-channel-extended-data-evt : (-> SSH-Application-Channel (Evtof (Pairof Symbol String)))
  (lambda [self]
    ((inst ssh-stdin-evt (Pairof Symbol String))
     (ssh-application-channel-extin self))))

(define ssh-channel-write-extended-data : (->* (SSH-Application-Channel String) (#:type Symbol) #:rest Any Void)
  (lambda [self #:type [type 'SSH-EXTENDED-DATA-STDERR] extfmt . argl]
    (define payload : String (if (null? argl) extfmt (apply format extfmt argl)))

    (write-special (make-ssh:msg:channel:extended:data #:recipient (ssh-channel-remote-id self) #:type type #:payload (string->bytes/utf-8 payload))
                   (ssh-application-channel-stdout self))
    (void)))

(define ssh-channel-close : (-> SSH-Application-Channel Void)
  (lambda [self]
    (write-special (make-ssh:msg:channel:close #:recipient (ssh-channel-remote-id self))
                   (ssh-application-channel-stdout self))
    (void)))

(define ssh-channel-wait : (-> SSH-Application-Channel Void)
  (lambda [self]
    (semaphore-wait (ssh-application-channel-done self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-wait-replies : (-> SSH-Application-Channel Byte (Listof Boolean))
  (lambda [self n]
    (let wait ([seilper : (Listof Boolean) null])
      (cond [(= (length seilper) n) (reverse seilper)]
            [else (wait (cons (sync/enable-break ((inst ssh-stdin-evt Boolean) (ssh-application-channel-ackin self)))
                              seilper))]))))

(define ssh-channel-write-request : (-> SSH-Application-Channel SSH-MSG-CHANNEL-REQUEST Void)
  (lambda [self request]
    (write-special request (ssh-application-channel-stdout self))
    (void)))

(define ssh-channel-request-pty : (-> SSH-Application-Channel (U String Bytes) #:cols Index #:rows Index #:width Index #:height Index #:modes Bytes
                                      [#:reply? Boolean] Void)
  (lambda [self name #:cols cols #:rows rows #:width width #:height height #:modes modes #:reply? [reply? #true]]
    (define request : SSH-MSG-CHANNEL-REQUEST
      (make-ssh:msg:channel:request:pty:req #:recipient (ssh-channel-remote-id self) #:reply? reply?
                                            #:TERM (if (string? name) (string->bytes/utf-8 name) name)
                                            #:cols cols #:rows rows #:width width #:height height #:modes modes))
    
    (ssh-channel-write-request self request)))

(define ssh-channel-request-window-change : (-> SSH-Application-Channel #:cols Index #:rows Index #:width Index #:height Index [#:reply? Boolean] Void)
  (lambda [self #:cols cols #:rows rows #:width width #:height height #:reply? [reply? #false]]
    (define request : SSH-MSG-CHANNEL-REQUEST
      (make-ssh:msg:channel:request:window:change #:recipient (ssh-channel-remote-id self) #:reply? reply?
                                                  #:cols cols #:rows rows #:width width #:height height))
    
    (ssh-channel-write-request self request)))

(define ssh-channel-request-xon/off : (-> SSH-Application-Channel Boolean [#:reply? Boolean] Void)
  (lambda [self client-can? #:reply? [reply? #false]]
    (define request : SSH-MSG-CHANNEL-REQUEST
      (make-ssh:msg:channel:request:xon:xoff #:recipient (ssh-channel-remote-id self) #:reply? reply?
                                             #:able? client-can?))
    
    (ssh-channel-write-request self request)))

(define ssh-channel-request-env : (-> SSH-Application-Channel (U String Bytes) (U String Bytes) [#:reply? Boolean] Void)
  (lambda [self name value #:reply? [reply? #false]]
    (define request : SSH-MSG-CHANNEL-REQUEST
      (make-ssh:msg:channel:request:env #:recipient (ssh-channel-remote-id self) #:reply? reply?
                                        #:name (if (string? name) (string->bytes/utf-8 name) name)
                                        #:value (if (string? value) (string->bytes/utf-8 value) value)))
    
    (ssh-channel-write-request self request)))

(define ssh-channel-request-exec : (-> SSH-Application-Channel (U Symbol String) [#:reply? Boolean] Any * Void)
  (lambda [self cmd #:reply? [reply? #true] . argl]
    (define partner : Index (ssh-channel-remote-id self))
    (define request : SSH-MSG-CHANNEL-REQUEST
      (if (string? cmd)
          (if (null? argl)
              (make-ssh:msg:channel:request:exec #:recipient partner #:reply? reply? #:command cmd)
              (make-ssh:msg:channel:request:exec #:recipient partner #:reply? reply? #:command (apply format cmd argl)))
          (if (eq? cmd 'shell)
              (make-ssh:msg:channel:request:shell #:recipient partner #:reply? reply?)
              (make-ssh:msg:channel:request:subsystem #:recipient partner #:reply? reply? #:name cmd))))
    
    (ssh-channel-write-request self request)))

(define ssh-channel-request-signal : (-> SSH-Application-Channel SSH-Session-Signal [#:reply? Boolean] Void)
  (lambda [self name #:reply? [reply? #false]]
    (define request : SSH-MSG-CHANNEL-REQUEST
      (make-ssh:msg:channel:request:signal #:recipient (ssh-channel-remote-id self) #:reply? reply? #:name name))
    
    (ssh-channel-write-request self request)))
  