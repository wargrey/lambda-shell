#lang typed/racket/base

(provide (all-defined-out))

(require racket/tcp)
(require racket/port)

(require "transport/identification.rkt")
(require "transport/message.rkt")

(require "assignment.rkt")
(require "exception.rkt")
(require "stdin.rkt")

(define ssh-connect : (-> String Integer
                          [#:protocol Positive-Flonum] [#:version (Option String)] [#:comments (Option String)] [#:timeout (Option Nonnegative-Real)]
                          (Values Input-Port Output-Port))
  (lambda [hostname port #:protocol [protoversion 2.0] #:version [softwareversion #false] #:comments [comments #false] #:timeout [timeout #false]]
    (parameterize ([current-custodian (make-custodian)])
      (define-values (/dev/pin /dev/pout) (make-pipe-with-specials 1 hostname hostname))
      (define protocol-exchange : Thread
        (thread (λ [] (with-handlers ([exn? (λ [[e : exn]] (write-special e /dev/pout))])
                        (define-values (/dev/tcpin /dev/tcpout) (tcp-connect/enable-break hostname port))
                        (define-values (identification idsize) (ssh-make-identification-string protoversion (or softwareversion "") comments))
                        (write-special /dev/tcpin /dev/pout)
                        (write-special /dev/tcpout /dev/pout)
                        (ssh-write-message /dev/tcpout identification idsize)
                        (write-special (ssh-read-server-identification /dev/tcpin) /dev/pout)
                        (write-special (ssh-read-transport-message /dev/tcpin) /dev/pout)
                        (thread-receive)))))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all (current-custodian)) (raise e))])
        (define /dev/tcpin : Input-Port (assert (read-byte-or-special /dev/pin) input-port?))
        (define /dev/tcpout : Output-Port (assert (read-byte-or-special /dev/pin) output-port?))
        (define server-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-connect))
        (displayln server-id)
        (define server-key : SSH-Message (ssh-read-special /dev/pin timeout SSH-Message? 'ssh-accept))
        (unless (= (SSH-Identification-protoversion server-id) protoversion)
          (throw exn:ssh:identification /dev/tcpin 'ssh-connect
                 "incompatible protoversion: ~a" (SSH-Identification-protoversion server-id)))
        (displayln server-key)
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
                        (write-special (ssh-read-client-identification /dev/tcpin) /dev/pout)
                        (write-special (ssh-read-transport-message /dev/tcpin) /dev/pout)))))
      (with-handlers ([exn? (λ [[e : exn]] (custodian-shutdown-all (current-custodian)) (raise e))])
        (define peer-id : SSH-Identification (ssh-read-special /dev/pin timeout SSH-Identification? 'ssh-accept))
        (displayln peer-id)
        (define peer-key : SSH-Message (ssh-read-special /dev/pin timeout SSH-Message? 'ssh-accept))
        (unless (= (SSH-Identification-protoversion peer-id) protoversion)
          (define message : String (format "incompatible protoversion: ~a" (SSH-Identification-protoversion peer-id)))
          (ssh-write-message /dev/tcpout message (string-length message))
          (throw exn:ssh:identification /dev/tcpin 'ssh-connect "~a" message))
        (define-values (identification idsize) (ssh-make-identification-string protoversion (or softwareversion "") comments))
        (ssh-write-message /dev/tcpout identification idsize)
        (displayln peer-key)
        (values /dev/tcpin /dev/tcpout)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(module+ main
  (with-handlers ([exn? (λ [[e : exn]] (displayln (exn-message e)))])
    (ssh-connect "github.com" 22))

  #;(define sshd : TCP-Listener (tcp-listen 2222 4 #true))
  #;(ssh-accept sshd #:timeout 0.618))
