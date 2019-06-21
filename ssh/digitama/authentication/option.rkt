#lang typed/racket/base

(provide (all-defined-out))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-userauth-option
  ([flags : (Listof Symbol)]
   [environments : (Listof (Pairof String String))]
   [command : (Option String)]
   [parameters : (Listof (Pairof Symbol String))])
  #:constructor-name ssh-userauth-option
  #:type-name SSH-Userauth-Option
  #:transparent)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-userauth-option : (-> [#:flags (Listof Symbol)] [#:parameters (Listof (Pairof Symbol String))]
                                       SSH-Userauth-Option)
  (lambda [#:flags [flags null] #:parameters [parameters null]]
    (ssh-userauth-option flags null #false parameters)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
