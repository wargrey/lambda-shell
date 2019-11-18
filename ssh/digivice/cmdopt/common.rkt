#lang typed/racket/base

(provide (all-defined-out))

(require digimon/echo)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define log-echo : (-> (Vector Symbol String Any (Option Symbol)) Void)
  (λ [log]
    (case (vector-ref log 0)
      [(info)    (echof "~a~n" #:fgcolor 'green  (vector-ref log 1))]
      [(warning) (echof "~a~n" #:fgcolor 'yellow (vector-ref log 1))]
      [(error)   (echof "~a~n" #:fgcolor 'red    (vector-ref log 1))]
      [(fatal)   (echof "~a~n" #:fgcolor 'red    (vector-ref log 1))]
      [else      (echof "~a~n" #:fgcolor 'gray   (vector-ref log 1))])))
