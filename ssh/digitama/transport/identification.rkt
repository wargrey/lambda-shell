#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-4.2

(provide (all-defined-out))

(require racket/path)
(require racket/string)

(require syntax/location)

(require typed/setup/getinfo)

(require "../diagnostics.rkt")

(require "../message/transport.rkt")
(require "../message/disconnection.rkt")

(require "../../configuration.rkt")

(struct ssh-identification
  ([protoversion : Positive-Flonum]
   [softwareversion : String]
   [comments : String]
   [raw : String])
  #:transparent
  #:type-name SSH-Identification)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-identification-string : (-> SSH-Configuration String)
  (lambda [rfc]
    (define version : String (if (string=? ($ssh-softwareversion rfc) "") (default-software-version) ($ssh-softwareversion rfc)))
    (define comments : String (or ($ssh-comments rfc) (default-comments)))
    (define identification : String
      (cond [(string=? comments "") (format "SSH-~a-~a" ($ssh-protoversion rfc) version)]
            [else (format "SSH-~a-~a ~a" ($ssh-protoversion rfc) version comments)]))
    (define-values (idsize maxsize) (values (string-length identification) (- ($ssh-longest-identification-length rfc) 2)))
    (substring identification 0 (min idsize maxsize))))

(define ssh-write-text : (->* (Output-Port String) (Fixnum) Void)
  (lambda [/dev/sshout idstring [idsize (string-length idstring)]]
    (write-string idstring /dev/sshout 0 idsize)
    (write-char #\return /dev/sshout)
    (write-char #\linefeed /dev/sshout)
    (flush-output /dev/sshout)))

(define ssh-read-server-identification : (-> Input-Port SSH-Configuration (U SSH-Identification SSH-MSG-DISCONNECT))
  (lambda [/dev/sshin rfc]
    (define line : String (make-string (max ($ssh-longest-identification-length rfc) ($ssh-longest-server-banner-length rfc))))
    (define message-handler : SSH-Server-Line-Handler ($ssh-server-banner-handler rfc))
    (or (let read-check-notify-loop : (Option SSH-MSG-DISCONNECT) ([count : Nonnegative-Fixnum 0])
          (cond [(< count ($ssh-maximum-server-banner-count rfc))
                 (read-string! line /dev/sshin 0 4)
                 (and (not (string-prefix? line "SSH-"))
                      (let ([maybe-end-index (read-server-message /dev/sshin line 4 ($ssh-longest-server-banner-length rfc))])
                        (cond [(and maybe-end-index) (message-handler (substring line 0 maybe-end-index)) (read-check-notify-loop (+ count 1))]
                              [else (make-ssh:disconnect:protocol:error #:source ssh-read-server-identification "banner message overlength: ~s" line)])))]
                [else (make-ssh:disconnect:protocol:error #:source ssh-read-server-identification "too many banner messages")]))
        (read-peer-identification /dev/sshin line 4 ($ssh-longest-identification-length rfc) rfc ssh-read-server-identification))))

(define ssh-read-client-identification : (-> Input-Port SSH-Configuration (U SSH-Identification SSH-MSG-DISCONNECT))
  (lambda [/dev/sshin option]
    (define line : String (make-string ($ssh-longest-identification-length option)))
    (read-string! line /dev/sshin 0 4)
    (cond [(string-prefix? line "SSH-") (read-peer-identification /dev/sshin line 4 ($ssh-longest-identification-length option) #false ssh-read-client-identification)]
          [else (make-ssh:disconnect:protocol:error #:source ssh-read-client-identification "not a SSH client: ~s" (substring line 0 4))])))

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

(define maybe-substring : (-> String Positive-Index Positive-Index (Option String))
  (lambda [src idx end]
    (and (> end idx)
         (substring src idx end))))

(define maybe-subfloat : (-> String Positive-Index Positive-Index (Option Positive-Flonum))
  (lambda [src idx end]
    (define maybe-string : (Option String) (maybe-substring src idx end))
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

(define read-peer-identification : (-> Input-Port String Positive-Index Positive-Index (Option SSH-Configuration) Procedure (U SSH-Identification SSH-MSG-DISCONNECT))
  (lambda [/dev/sshin destline idx0 idx-max rfc src]
    (define-values (maybe-end-idx maybe-protoversion maybe-softwareversion maybe-comments)
      (let read-loop : (Values (Option Positive-Index) (Option Positive-Flonum) (Option String) (Option String))
        ([idx : Positive-Index idx0]
         [end-idx : Positive-Index idx0]
         [token-idx : Positive-Index idx0]
         [protoversion : (Option Positive-Flonum) #false]
         [softwareversion : (Option String) #false]
         [comments : (Option String) #false]
         [space? : Boolean #false])
        (define next-idx : Positive-Fixnum (+ idx 1))
        (cond [(> next-idx idx-max) (values #false #false #false #false)]
              [else (let ([maybe-ch : (U Char EOF) (read-char /dev/sshin)])
                      (cond [(eq? maybe-ch #\return)
                             (read-loop next-idx end-idx token-idx protoversion
                                        (or softwareversion (maybe-substring destline token-idx end-idx))
                                        (and softwareversion space? (maybe-substring destline token-idx end-idx))
                                        space?)]
                            [(or (eq? maybe-ch #\linefeed) (eof-object? maybe-ch))
                             (values end-idx protoversion
                                     (or softwareversion (maybe-substring destline token-idx end-idx))
                                     (and softwareversion space? (or comments (maybe-substring destline token-idx end-idx))))]
                            [(eq? maybe-ch #\-)
                             (string-set! destline idx maybe-ch)
                             (read-loop next-idx next-idx (if (not protoversion) next-idx token-idx)
                                        (or protoversion (maybe-subfloat destline token-idx idx)) softwareversion comments space?)]
                            [(eq? maybe-ch #\space)
                             (string-set! destline idx maybe-ch)
                             (read-loop next-idx end-idx (if space? token-idx next-idx)
                                        protoversion (or softwareversion (maybe-substring destline token-idx idx))
                                        comments #true)]
                            [else (string-set! destline idx maybe-ch)
                                  (read-loop next-idx next-idx token-idx protoversion softwareversion comments space?)]))])))
    (let ([idstr (substring destline 0 (or maybe-end-idx idx-max))])
      (cond [(not (and maybe-end-idx maybe-protoversion maybe-softwareversion))
             (make-ssh:disconnect:protocol:error #:source src "invalid identification: ~s" idstr)]
            [(and rfc (not (= maybe-protoversion ($ssh-protoversion rfc))))
             (make-ssh:disconnect:protocol:version:not:supported #:source src "incompatible protoversion: ~a(~s)" maybe-protoversion idstr)]
            [else (ssh-identification maybe-protoversion maybe-softwareversion (or maybe-comments "") idstr)]))))
