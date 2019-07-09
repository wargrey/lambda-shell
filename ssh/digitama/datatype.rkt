#lang typed/racket/base

(provide (all-defined-out))
(provide (for-syntax (all-defined-out)))

(require (for-syntax racket/base))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax (ssh-struct-field <declaration>)
  (define declaration (syntax-e <declaration>))
  (define <field> (car declaration))
  (define <kw-name> (datum->syntax <field> (string->keyword (symbol->string (syntax-e <field>)))))
  (define-values (<argls> <value>)
    (syntax-case <declaration> []
      [(field FieldType) (values #'[field : FieldType] #'field)]

      ; TODO: why it fails when `defval` is using other field names?
      [(field FieldType defval) (values #'[field : (U FieldType Void) (void)] #'(if (void? field) defval field))]
      [_ (raise-syntax-error 'define-ssh-message-field "malformed field declaration" <declaration>)]))
  (values <kw-name> <argls> <value>))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-type (SSH-Bytes->Datum t) (->* (Bytes) (Natural) (Values t Natural)))
(define-type (SSH-Datum->Bytes t) (case-> [-> t Bytes] [->* (t Bytes) (Natural) Natural]))
(define-type (SSH-Void T v) T)

(define ssh-ghost-length : (-> Any Zero)
  (lambda [?]
    0))

(define ssh-ghost->bytes : (SSH-Datum->Bytes Any)
  (case-lambda
      [(bool) #""]
      [(bool pool) (ssh-ghost->bytes bool pool 0)]
      [(bool pool offset) offset]))

(define ssh-values : (SSH-Bytes->Datum Bytes)
  (lambda [braw [offset 0]]
    (define end : Index (bytes-length braw))
    (values (subbytes braw offset end)
            end)))

(define ssh-bytes->bytes : (SSH-Datum->Bytes Bytes)
  (case-lambda
    [(bs) bs]
    [(bs pool) (ssh-bytes->bytes bs pool 0)]
    [(bs pool offset) (let ([bsize (bytes-length bs)])
                        (bytes-copy! pool offset bs 0 bsize)
                        (+ offset bsize))]))

(define ssh-namelist-port : (-> (Listof Symbol) Output-Port)
  (lambda [names]
    (define /dev/nout (open-output-bytes '/dev/nout))

    (when (pair? names)
      (let count ([name : Symbol (car names)]
                  [names : (Listof Symbol) (cdr names)])
        (write name /dev/nout)

        (when (pair? names)
          (write-char #\, /dev/nout)
          
          (count (car names)
                 (cdr names)))))

    /dev/nout))
