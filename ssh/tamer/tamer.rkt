#lang racket/base

(provide (all-defined-out))
(provide (all-from-out digimon/tamer))

(require digimon/tamer)

(require "../digitama/transport/identification.rkt")

(define the-name
  (let-values ([(name version) (software-version)])
    (tech name)))
