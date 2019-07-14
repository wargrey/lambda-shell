#lang typed/racket/base

(provide (all-defined-out))

(require "channel.rkt")

(require "../message.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-window-upsize : Index (assert (- (expt 2 32) 1) index?))

(struct ssh-channel-port
  ([entity : SSH-Channel]
   [partner : (Option Index)] ; #false => waiting for the confirmation 
   [incoming-window : Index]
   [outgoing-window : Index]
   [parcel : Bytes]
   [incoming-upwindow : Index]
   [outgoing-upwindow : Index]
   [pending-data : (Listof SSH-Message)]
   [incoming-eof? : Boolean]
   [outgoing-eof? : Boolean]
   [incoming-traffic : Natural]
   [outgoing-traffic : Natural])
  #:type-name SSH-Channel-Port
  #:mutable)

(define ssh-channel-incoming-partner : (-> SSH-Channel-Port (Option Index))
  (lambda [self]
    (and (not (ssh-channel-port-incoming-eof? self))
         (ssh-channel-port-partner self))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-channel-eq-uuid : (case-> [Any -> Index]
                                      [Any HashTableTop -> Index])
  (case-lambda
    [(object)
     (let-values ([(bodybits randbits) (values 28 4)])
       (assert (let ([body (bitwise-bit-field (eq-hash-code object) 0 bodybits)]
                     [rand (random (arithmetic-shift 1 randbits))])
                 (bitwise-ior (arithmetic-shift rand bodybits) body))
               index?))]
    [(object uuidbase)
     (let uuid ([composed-object : Any object])
       (let ([id (ssh-channel-eq-uuid composed-object)])
         (cond [(not (hash-has-key? uuidbase id)) id]
               [else (uuid (cons composed-object id))])))]))

