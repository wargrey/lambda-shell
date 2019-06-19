#lang typed/racket/base

(provide (all-defined-out))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct ssh-userauth-option
  ([flags : (Listof Symbol)]
   [environments : (Listof (Pairof String String))]
   [command : (Option String)])
  #:constructor-name ssh-userauth-option
  #:type-name SSH-Userauth-Option
  #:transparent)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-ssh-userauth-option : (-> [#:flags (Listof Symbol)] [#:environments (Listof (Pairof String String))] [#:command (Option String)]
                                       SSH-Userauth-Option)
  (lambda [#:flags [flags null] #:environments [envs null] #:command [cmd #false]]
    (ssh-userauth-option flags envs cmd)))
