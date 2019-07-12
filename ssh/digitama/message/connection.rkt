#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")

(require "../assignment/connection.rkt")

(require "../../datatype.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4254
  [SSH_MSG_GLOBAL_REQUEST            80 ([name : Symbol] [replay? : Boolean #true]) #:case name]
  [SSH_MSG_REQUEST_SUCCESS           81 ([details : (SSH-Bytes #false) #""])]
  [SSH_MSG_REQUEST_FAILURE           82 ([details : (SSH-Bytes #false) #""])]
  [SSH_MSG_CHANNEL_OPEN              90 ([type : Symbol] [sender : Index] [window-size : Index] [packet-capacity : Index]) #:case type]
  [SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91 ([recipient : Index] [sender : Index] [window-size : Index] [packet-capacity : Index] [details : (SSH-Bytes #false) #""])]
  [SSH_MSG_CHANNEL_OPEN_FAILURE      92 ([recipient : Index]
                                         [reason : (SSH-Symbol SSH-Channel-Failure-Reason)]
                                         [description : String (symbol->string reason)]
                                         [language : Symbol '||])]
  [SSH_MSG_CHANNEL_WINDOW_ADJUST     93 ([recipient : Index] [addsize : Index])]
  [SSH_MSG_CHANNEL_DATA              94 ([recipient : Index] [body : Bytes])]
  [SSH_MSG_CHANNEL_EXTENDED_DATA     95 ([recipient : Index] [type : (SSH-Symbol SSH-Channel-Data-Type) 'SSH-EXTENDED-DATA-STDERR] [body : Bytes])]
  [SSH_MSG_CHANNEL_EOF               96 ([recipient : Index])]
  [SSH_MSG_CHANNEL_CLOSE             97 ([recipient : Index])]
  [SSH_MSG_CHANNEL_REQUEST           98 ([recipient : Index] [type : Symbol] [reply? : Boolean #true]) #:case type]
  [SSH_MSG_CHANNEL_SUCCESS           99 ([recipient : Index])]
  [SSH_MSG_CHANNEL_FAILURE          100 ([recipient : Index])])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define SSH:MSG:REQUEST:SUCCESS : SSH-MSG-REQUEST-SUCCESS (make-ssh:msg:request:success))
(define SSH:MSG:REQUEST:FAILURE : SSH-MSG-REQUEST-FAILURE (make-ssh:msg:request:failure))
