#lang typed/racket/base

(provide (all-defined-out))
(provide (rename-out [make-$ssh make-ssh-configuration]))

(require digimon/struct)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type SSH-Server-Line-Handler (-> String Void))
(define-type SSH-Debug-Message-Handler (-> Boolean String Symbol Void))

(define-configuration $ssh : SSH-Configuration #:format "default-ssh-~a"
  ([protoversion : Positive-Flonum 2.0]
   [softwareversion : String ""]
   [comments : (Option String) #false]
   [longest-identification-length : Positive-Index 255]
   
   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   [payload-capacity : Index 32768]
   [minimum-key-bits : Positive-Index 3072]

   [timeout : Index 0] ; seconds
   [rekex-traffic : Positive-Integer (* 1024 1024 1024)]

   [debug-message-handler : SSH-Debug-Message-Handler void]

   [server-banner-handler : SSH-Server-Line-Handler void]
   [maximum-server-banner-count : Positive-Index 1024]
   [longest-server-banner-length : Positive-Index 8192]

   [pretty-log-packet-level : (Option Log-Level) #false]

   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   [userauth-timeout : Index 600] ; seconds
   [userauth-retry : Index 20]

   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   [channel-packet-capacity : Index 32768] ; 32KB
   [channel-initial-window-size : Index 2097152] ; 2MB
   
   [disabled-channel-types : (Listof Symbol) null]
   [allowed-envs : (Listof Bytes) (list #"LC_ALL" #"LC_CTYPE")]))
