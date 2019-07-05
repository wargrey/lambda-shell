#lang typed/racket/base

(provide (all-defined-out))
(provide SSH-Option-Value)

(require "option.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-userauth-option
  ([flags : (Listof Symbol)]
   [environments : (Listof (Pairof String String))]
   [force-command : (Option String)]
   [expiry : (Option Natural)]
   [form : (Listof String)]
   [permitlisten : (Listof (Pairof (Option String) Index))]
   [permitopen : (Listof (Pairof String Index))]
   [principals : (Listof String)]
   [tunnel : (Option String)])
  #:constructor-name ssh-userauth-option
  #:type-name SSH-Userauth-Option
  #:transparent)

(struct ssh-user
  ([name : Symbol]
   [option : SSH-Userauth-Option])
  #:type-name SSH-User
  #:constructor-name make-ssh-user
  #:transparent)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-userauth-option : (-> [#:flags (Listof Symbol)] [#:parameters (Listof (Pairof Symbol SSH-Option-Value))] [#:source Input-Port] SSH-Userauth-Option)
  (lambda [#:flags [flags null] #:parameters [parameters null] #:source [source (current-input-port)]]
    (ssh-userauth-option flags
                         (ssh-userauth-option-map 'environment parameters source ssh-userauth-check-environment)
                         (ssh-userauth-option-ref 'command parameters)
                         (ssh-userauth-option-ref 'expiry-time parameters source ssh-userauth-check-expiry-localtime)
                         (or (ssh-userauth-option-ref 'from parameters source ssh-userauth-split) null)
                         (ssh-userauth-option-map 'permitlisten parameters source ssh-userauth-check-port)
                         (ssh-userauth-option-map 'permitopen parameters source ssh-userauth-check-host:port)
                         (or (ssh-userauth-option-ref 'principals parameters source ssh-userauth-split) null)
                         (ssh-userauth-option-ref 'tunnel parameters))))
