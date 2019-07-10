#lang typed/racket/base

(provide (all-defined-out))

(require "../message/transport.rkt")

(require typed/racket/unsafe)

(unsafe-require/typed
 racket/base
 [call-with-continuation-prompt (All (b d) (-> (-> b) (Prompt-Tagof Any Any) (-> SSH-MSG-DISCONNECT d) (U b d)))]
 [abort-current-continuation (All (a) (-> (Prompt-Tagof Any Any) a Nothing))])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NOTE: (Prompt-Tagof Any (-> a ... a b)) cannot be type-checked meanwhile since it involves 'chaperone/sc'

(define default-ssh-transport-prompt : (Parameterof (Prompt-Tagof Any Any)) (make-parameter (make-continuation-prompt-tag)))

(define ssh-prompt : (All (a b) (case-> [(Option Symbol) (-> a) Output-Port -> (U Void a)]
                                        [(Option Symbol) (-> a) (-> SSH-MSG-DISCONNECT b) -> (U a b)]))
  (lambda [tagname do-task at-collapse]
    (define current-prompt : (Prompt-Tagof Any Any)
      (cond [(not tagname) (make-continuation-prompt-tag)]
            [else (make-continuation-prompt-tag tagname)]))

    (parameterize ([default-ssh-transport-prompt current-prompt])
      (call-with-continuation-prompt do-task current-prompt
        (cond [(not (output-port? at-collapse)) at-collapse]
              [else (λ [[eof-msg : SSH-MSG-DISCONNECT]] : Void
                      (void (write-special eof-msg at-collapse)))])))))

(define ssh-collapse : (-> SSH-MSG-DISCONNECT Nothing)
  (lambda [msg]
    (abort-current-continuation (default-ssh-transport-prompt) msg)))
