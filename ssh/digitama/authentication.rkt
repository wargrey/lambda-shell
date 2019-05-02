#lang typed/racket/base

(provide (all-defined-out))

(require "transport.rkt")
(require "diagnostics.rkt")

(require "../message.rkt")
(require "../assignment.rkt")
(require "../configuration.rkt")

(struct ssh-user-port ssh-port
  ([username : Symbol])
  #:type-name SSH-User-Port)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-sync-handle-feedback : (-> Input-Port Output-Port Output-Port SSH-MSG-KEXINIT (Listof Symbol) SSH-Configuration Boolean Void)
  (lambda [/dev/tcpin /dev/tcpout /dev/sshout kexinit services rfc server?]
    (define /dev/sshin : (Evtof Any) (wrap-evt (thread-receive-evt) (λ [[e : (Rec x (Evtof x))]] (thread-receive))))
    (define rekex-traffic : Natural ($ssh-rekex-traffic rfc))
    (define self : Thread (current-thread))
    
    (let sync-handle-feedback-loop : Void ([maybe-rekex : (Option Thread) #false]
                                           [kexinit : SSH-MSG-KEXINIT kexinit])
      (define evt : Any
        (cond [else (sync/enable-break /dev/sshin (or maybe-rekex /dev/tcpin))]))

      (define-values (maybe-task incoming++ outgoing++)
        (cond [else (values maybe-rekex 0 0)]))
      
      (sync-handle-feedback-loop maybe-task (if (ssh:msg:kexinit? evt) evt kexinit)))))
