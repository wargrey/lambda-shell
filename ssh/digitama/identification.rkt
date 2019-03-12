#lang typed/racket/base

(provide (all-defined-out))

(require racket/path)
(require racket/string)

(require syntax/location)

(require typed/setup/getinfo)

(define SSH-LONGEST-IDENTIFICATION-LENGTH : Positive-Index 255)
(define SSH-LONGEST-SERVER-MESSAGE-LENGTH : Positive-Index 1024)

(define make-identification : (-> Positive-Flonum String (Option String) (Values String Fixnum))
  (lambda [protocol maybe-version maybe-comments]
    (define version : String (if (string=? maybe-version "") (default-software-version) maybe-version))
    (define comments : String (or maybe-comments (default-comments)))
    (define identification : String
      (cond [(string=? comments "") (format "SSH-~a-~a" protocol version)]
            [else (format "SSH-~a-~a ~a" protocol version comments)]))
    (define-values (idsize maxsize) (values (string-length identification) (- SSH-LONGEST-IDENTIFICATION-LENGTH 2)))
    (values identification (min idsize maxsize))))

(define read-server-identification : (-> Input-Port String)
  (lambda [/dev/sshin]
    (define line : String (make-string (max SSH-LONGEST-IDENTIFICATION-LENGTH SSH-LONGEST-SERVER-MESSAGE-LENGTH)))
    (let read-check-loop ()
      (read-string! line /dev/sshin 0 4)
      (unless (string-prefix? line line)
        (let read-log-loop ([idx : Positive-Index 4])
          (define next-idx : Positive-Fixnum (+ idx 1))
          (define maybe-eof : (U EOF Integer) (read-string! line /dev/sshin idx next-idx))
          (void))))
    line))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
