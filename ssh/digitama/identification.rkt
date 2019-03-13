#lang typed/racket/base

(provide (all-defined-out))

(require racket/path)
(require racket/string)

(require syntax/location)

(require typed/setup/getinfo)

(require "exception.rkt")

(define-type SSH-Server-Message-Handler (-> String Void))

(struct SSH-Identification
  ([protoversion : Positive-Flonum]
   [softwareversion : String]
   [comments : (Option String)]
   [raw : String])
  #:transparent)


(define SSH-LONGEST-IDENTIFICATION-LENGTH : Positive-Index 255)
(define SSH-LONGEST-SERVER-MESSAGE-LENGTH : Positive-Index 1024)

(define default-ssh-server-message-handler : (Parameterof SSH-Server-Message-Handler) (make-parameter void))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define make-identification-string : (-> Positive-Flonum String (Option String) (Values String Fixnum))
  (lambda [protocol maybe-version maybe-comments]
    (define version : String (if (string=? maybe-version "") (default-software-version) maybe-version))
    (define comments : String (or maybe-comments (default-comments)))
    (define identification : String
      (cond [(string=? comments "") (format "SSH-~a-~a" protocol version)]
            [else (format "SSH-~a-~a ~a" protocol version comments)]))
    (define-values (idsize maxsize) (values (string-length identification) (- SSH-LONGEST-IDENTIFICATION-LENGTH 2)))
    (values identification (min idsize maxsize))))

(define write-identification : (-> Output-Port String Fixnum Void)
  (lambda [/dev/sshout idstring idsize]
    (write-string idstring /dev/sshout 0 idsize)
    (write-char #\return /dev/sshout)
    (write-char #\linefeed /dev/sshout)))

(define read-server-identification : (-> Input-Port SSH-Identification)
  (lambda [/dev/sshin]
    (define line : String (make-string (max SSH-LONGEST-IDENTIFICATION-LENGTH SSH-LONGEST-SERVER-MESSAGE-LENGTH)))
    (define message-handler : SSH-Server-Message-Handler (default-ssh-server-message-handler))
    (let read-check-notify-loop ()
      (read-string! line /dev/sshin 0 4)
      (unless (string-prefix? line "SSH-")
        (let ([maybe-end-index (read-server-message /dev/sshin line 4 SSH-LONGEST-SERVER-MESSAGE-LENGTH)])
          (cond [(not maybe-end-index) (throw exn:ssh:defense /dev/sshin 'protocol-exchange "message is too long: ~s" line)]
                [else (message-handler (substring line 0 maybe-end-index))])
          (read-check-notify-loop))))
    (read-peer-identification! /dev/sshin line 4 SSH-LONGEST-IDENTIFICATION-LENGTH)))

(define read-client-identification : (-> Input-Port SSH-Identification)
  (lambda [/dev/sshin]
    (define line : String (make-string SSH-LONGEST-IDENTIFICATION-LENGTH))
    (read-string! line /dev/sshin 0 4)
    (cond [(string-prefix? line "SSH-") (read-peer-identification! /dev/sshin line 4 SSH-LONGEST-IDENTIFICATION-LENGTH)]
          [else (throw exn:ssh:identification /dev/sshin 'protocol-exchange "not an SSH peer: ~s" (substring line 0 4))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define default-software-version : (-> String)
  (lambda []
    (define info-ref (collection-ref (quote-source-file)))
    (cond [(not info-ref) (default-comments)]
          [else (format "~a_~a"
                  (info-ref 'software-version)
                  (info-ref 'version))])))

(define default-comments : (-> String)
  (lambda []
    (string-append "Racket-v" (version))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define collection-ref : (->* () (Path-String) (Option Info-Ref))
  (lambda [[dir (current-directory)]]
    (define info-ref (get-info/full dir))
    (or info-ref
        (let-values ([(base name dir?) (split-path (simple-form-path dir))])
          (and (path? base) (collection-ref base))))))

(define list->maybe-string : (-> (Listof Char) (Option String))
  (lambda [snekot]
    (and (pair? snekot)
         (list->string (reverse snekot)))))

(define list->maybe-float : (-> (Listof Char) (Option Positive-Flonum))
  (lambda [snekot]
    (define maybe-string : (Option String) (list->maybe-string snekot))
    (and (string? maybe-string)
         (let ([maybe-num (string->number maybe-string)])
           (and (real? maybe-num)
                (let ([fl (real->double-flonum maybe-num)])
                  (and (positive? fl) fl)))))))

(define read-server-message : (-> Input-Port String Positive-Index Positive-Index (Option Positive-Index))
  (lambda [/dev/sshin destline idx0 idx-max]
    (let read-loop : (Option Positive-Index) ([idx : Positive-Index idx0]
                                              [end-idx : Positive-Index idx0])
      (define next-idx : Positive-Fixnum (+ idx 1))
      (and (<= next-idx idx-max)
           (let ([maybe-ch : (U Char EOF) (read-char /dev/sshin)])
             (cond [(eq? maybe-ch #\return) (read-loop next-idx end-idx)]
                   [(or (eq? maybe-ch #\linefeed) (eof-object? maybe-ch)) end-idx]
                   [else (string-set! destline idx maybe-ch) (read-loop next-idx next-idx)]))))))

(define read-peer-identification! : (-> Input-Port String Positive-Index Positive-Index SSH-Identification)
  (lambda [/dev/sshin destline idx0 idx-max]
    (define-values (maybe-end-idx maybe-protoversion maybe-softwareversion maybe-comments)
      (let read-loop : (Values (Option Positive-Index) (Option Positive-Flonum) (Option String) (Option String))
        ([idx : Positive-Index idx0]
         [end-idx : Positive-Index idx0]
         [snekot : (Listof Char) null]
         [protoversion : (Option Positive-Flonum) #false]
         [softwareversion : (Option String) #false]
         [comments : (Option String) #false]
         [minus? : Boolean #false]
         [space? : Boolean #false])
        (define next-idx : Positive-Fixnum (+ idx 1))
        (cond [(> next-idx idx-max) (values #false #false #false #false)]
              [else (let ([maybe-ch : (U Char EOF) (read-char /dev/sshin)])
                      (cond [(eq? maybe-ch #\return)
                             (read-loop next-idx end-idx null protoversion
                                        (or softwareversion (list->maybe-string snekot))
                                        (and softwareversion (list->maybe-string snekot))
                                        minus? space?)]
                            [(or (eq? maybe-ch #\linefeed) (eof-object? maybe-ch))
                             (values end-idx protoversion
                                     (or softwareversion (list->maybe-string snekot))
                                     (and softwareversion (or comments (list->maybe-string snekot))))]
                            [(eq? maybe-ch #\-)
                             (string-set! destline idx maybe-ch)
                             (define maybe-protoversion : (Option Positive-Flonum) (list->maybe-float snekot))
                             (when (not space?)
                               (when (and minus?)
                                 (throw exn:ssh:identification /dev/sshin 'protocol-exchange "invalid softwareversion: ~s"
                                        (substring destline 0 next-idx)))
                               (unless maybe-protoversion
                                 (throw exn:ssh:identification /dev/sshin 'protocol-exchange "invalid protoversion: ~s"
                                        (substring destline 0 idx))))
                             (read-loop next-idx end-idx (if space? (cons maybe-ch snekot) null)
                                        (or protoversion maybe-protoversion) softwareversion comments #true space?)]
                            [(eq? maybe-ch #\space)
                             (string-set! destline idx maybe-ch)
                             (read-loop next-idx end-idx (if space? (cons maybe-ch snekot) null)
                                        protoversion (or softwareversion (list->maybe-string snekot))
                                        comments minus? #true)]
                            [else (string-set! destline idx maybe-ch)
                                  (read-loop next-idx next-idx (cons maybe-ch snekot) protoversion softwareversion comments minus? space?)]))])))
    (or (and maybe-end-idx maybe-protoversion maybe-softwareversion
             (SSH-Identification maybe-protoversion maybe-softwareversion maybe-comments
                                 (substring destline 0 maybe-end-idx)))
        (throw exn:ssh:identification /dev/sshin 'protocol-exchange "invalid identification: ~s"
               (substring destline 0 (or maybe-end-idx idx-max))))))
