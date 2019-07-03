#lang typed/racket/base

(provide (all-defined-out))

(require "../message.rkt")
(require "../algorithm/random.rkt")

(require "../assignment.rkt")
(require "../../assignment.rkt")
(require "../../datatype.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-ssh-messages
  ; for http://tools.ietf.org/html/rfc4254
  [SSH_MSG_GLOBAL_REQUEST            80 ([name : Symbol] [replay? : Boolean #true]) #:case name]
  [SSH_MSG_REQUEST_SUCCESS           81 ([details : Bytes #""])]
  [SSH_MSG_REQUEST_FAILURE           82 ()]
  [SSH_MSG_CHANNEL_OPEN              90 ([type : Symbol] [sender : Index] [window-size : Index] [packet-upsize : Index]) #:case type]
  [SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91 ([recipient : Index] [sender : Index] [window-size : Index] [packet-upsize : Index] [details : Bytes #""])]
  [SSH_MSG_CHANNEL_OPEN_FAILURE      92 ([recipient : Index]
                                         [reason : (SSH-Symbol SSH-Channel-Failure-Reason)]
                                         [descripion : String (symbol->string reason)]
                                         [language : Symbol '||])]
  [SSH_MSG_CHANNEL_WINDOW_ADJUST     93 ([recipient : Index] [addsize : Index])]
  [SSH_MSG_CHANNEL_DATA              94 ([recipient : Index] [body : SSH-BString])]
  [SSH_MSG_CHANNEL_EXTENDED_DATA     95 ([recipient : Index] [type : (SSH-Symbol SSH-Channel-Data-Type) 'SSH-EXTENDED-DATA-STDERR] [body : SSH-BString])]
  [SSH_MSG_CHANNEL_EOF               96 ([recipient : Index])]
  [SSH_MSG_CHANNEL_CLOSE             97 ([recipient : Index])]
  [SSH_MSG_CHANNEL_REQUEST           98 ([recipient : Index] [type : Symbol] [reply? : Boolean #true]) #:case type]
  [SSH_MSG_CHANNEL_SUCCESS           99 ([recipient : Index])]
  [SSH_MSG_CHANNEL_FAILURE          100 ([recipient : Index])])
