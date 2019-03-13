#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "identification.rkt")
(require "transport.rkt")
(require "exception.rkt")

(define ssh-connect : (-> String Integer
                          [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)] [#:timeout (Option Nonnegative-Real)]
                          (Values Input-Port Output-Port))
  (lambda [hostname port #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false] #:timeout [timeout #false]]
    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials))
      (define protocol-exchange : Thread
        (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/pout))])
                        (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
                        (define-values (identification idsize) (make-identification-string protoversion (or softwareversion "") comments))
                        (write-special /dev/tcpin /dev/pout)
                        (write-special /dev/tcpout /dev/pout)
                        (write-identification /dev/tcpout identification idsize)
                        (write-special (read-server-identification /dev/tcpin) /dev/pout)))))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all (current-custodian)) (raise e))])
        (define /dev/tcpin : Input-Port (assert (read-byte-or-special /dev/pin) input-port?))
        (define /dev/tcpout : Output-Port (assert (read-byte-or-special /dev/pin) output-port?))
        (unless (cond [(not timeout) (sync/enable-break /dev/pin)]
                      [else (sync/timeout/enable-break timeout /dev/pin)])
          (ssh-raise-timeout-error /dev/tcpin 'ssh-connect timeout))
        (define maybe-server-id (read-byte-or-special /dev/pin))
        (when (exn? maybe-server-id) (raise maybe-server-id))
        (define server-id : SSH-Identification (assert maybe-server-id SSH-Identification?))
        (unless (= (SSH-Identification-protoversion server-id) protoversion)
          (throw exn:ssh:identification /dev/tcpin 'ssh-connect "incompatible protoversion: ~a"
                 (SSH-Identification-protoversion server-id)))
        (displayln server-id)
        (values /dev/tcpin /dev/tcpout)))))

(define ssh-accept : (-> TCP-Listener
                         [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)] [#:timeout (Option Nonnegative-Real)]
                         (Values Input-Port Output-Port))
  (lambda [listener #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false] #:timeout [timeout #false]]
    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/tcpin /dev/tcpout) (tcp-accept/enable-break listener))
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials))
      (define protocol-exchange : Thread
        (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/pout))])
                        (write-special (read-client-identification /dev/tcpin) /dev/pout)))))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all (current-custodian)) (raise e))])
        (unless (cond [(not timeout) (sync/enable-break /dev/tcpin)]
                      [else (sync/timeout/enable-break timeout /dev/tcpin)])
          (ssh-raise-timeout-error /dev/tcpin 'ssh-accept timeout))
        (define maybe-server-id (read-byte-or-special /dev/pin))
        (when (exn? maybe-server-id) (raise maybe-server-id))
        (define server-id : SSH-Identification (assert maybe-server-id SSH-Identification?))
        (unless (= (SSH-Identification-protoversion server-id) protoversion)
          (throw exn:ssh:identification /dev/tcpin 'ssh-connect "incompatible protoversion: ~a"
                 (SSH-Identification-protoversion server-id)))
        (define-values (identification idsize) (make-identification-string protoversion (or softwareversion "") comments))
        (write-identification /dev/tcpout identification idsize)
        (values /dev/tcpin /dev/tcpout)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (with-handlers ([exn? (λ [[e : exn]] (displayln (exn-message e)))])
    (ssh-connect "192.168.18.118" 22 #:timeout 0.618)))
