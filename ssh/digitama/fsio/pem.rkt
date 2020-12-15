#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc7468#section-2

(provide (all-defined-out))

(require racket/string)
(require racket/symbol)
(require racket/path)

(require digimon/binscii)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct pem-key
  ([src : Path]
   [type : Symbol]
   [raw : Bytes])
  #:constructor-name make-pem-key
  #:type-name PEM-Key
  #:transparent)

(define pem-base64-line-size : Positive-Byte 64)

(define read-directory-private-keys : (->* () (Path-String) (Listof PEM-Key))
  (lambda [[.ssh (build-path (find-system-path 'home-dir) ".ssh")]]
    (cond [(not (directory-exists? .ssh)) null]
          [else (let read-key ([syek : (Listof PEM-Key) null]
                               [files : (Listof Path) (directory-list .ssh #:build? #true)])
                  (cond [(null? files) (reverse syek)]
                        [(not (file-exists? (car files))) (read-key syek (cdr files))]
                        [(path-get-extension (car files)) (read-key syek (cdr files))]
                        [else (let-values ([(key BEGIN END) (pem-read (car files))])
                                (cond [(not (and BEGIN (eq? BEGIN END))) (read-key syek (cdr files))]
                                      [else (read-key (cons (make-pem-key (car files) BEGIN key) syek)
                                                      (cdr files))]))]))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pem-write : (-> Bytes (U Output-Port Path-String) #:label (U Symbol String) Void)
  (lambda [key-octets /dev/keyout #:label label-raw]
    (if (not (output-port? /dev/keyout))
        (call-with-output-file* /dev/keyout #:exists 'truncate/replace
          (λ [[/dev/keyout : Output-Port]]
            (pem-write key-octets /dev/keyout #:label label-raw)))
        (let-values ([(BEGIN END) (pem-encapsulation-boundaries label-raw)])
          (displayln BEGIN /dev/keyout)

          (let* ([data (base64-encode key-octets)]
                 [size (bytes-length data)])
            (let write-base64-lines ([idx : Natural 0])
              (when (< idx size)
                (define end : Natural (+ idx (min (abs (- size idx)) pem-base64-line-size)))
                
                (write-bytes data /dev/keyout idx end)
                (newline /dev/keyout)
                
                (write-base64-lines end))))
    
          (displayln END /dev/keyout)
    
          (flush-output /dev/keyout)))))

(define pem-read : (-> (U Input-Port Path-String) (Values Bytes (Option Symbol) (Option Symbol)))
  (lambda [/dev/keyin]
    (if (not (input-port? /dev/keyin))
        (let ([octets.begin.end
               (call-with-input-file* /dev/keyin
                 (λ [[/dev/rsain : Input-Port]] : (List Bytes (Option Symbol) (Option Symbol))
                   (define-values (octets BEGIN END) (pem-read /dev/rsain))
                   (list octets BEGIN END)))])
          (values (car octets.begin.end) (cadr octets.begin.end) (caddr octets.begin.end)))
        (let ([BEGIN (let read-head-boundary : (Option Symbol) ()
                       (define maybe-line : (U Bytes EOF) (read-bytes-line /dev/keyin))
                       (cond [(eof-object? maybe-line) #false]
                             [(regexp-match? #px"^[-]+\\s*BEGIN " maybe-line) (pem-encapsulation-label maybe-line)]
                             [else (read-head-boundary)]))])
          
          (define-values (base64s END)
            (let read-key-line : (Values (Listof Bytes) (Option Symbol)) ([s46esab : (Listof Bytes) null]
                                                                          [base64-realm : Boolean #false])
              (define maybe-base64-line : (U Bytes EOF) (read-bytes-line /dev/keyin))
              (cond [(eof-object? maybe-base64-line) (values (reverse s46esab) #false)]
                    [(regexp-match? #px"^[-]+\\s*END " maybe-base64-line) (values (reverse s46esab) (pem-encapsulation-label maybe-base64-line))]
                    [(and (not base64-realm) (regexp-match? #px"^\\s*$" maybe-base64-line)) (read-key-line s46esab base64-realm)]
                    [(and (not base64-realm) (regexp-match? #px"[:,]" maybe-base64-line)) (values null #false)] ; TODO, implement PKCS#8
                    [else (read-key-line (cons (pem-base64-line-trim maybe-base64-line) s46esab) #true)])))

          (values (base64-decode (apply bytes-append base64s))
                  BEGIN END)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define pem-encapsulation-boundaries : (-> (U Symbol String) (Values String String))
  (lambda [label-raw]
    (define label : String
      (string-upcase
       (string-replace
        (cond [(string? label-raw) label-raw]
              [else (symbol->immutable-string label-raw)])
        "-" " ")))

    (values (format "-----BEGIN ~a-----" label)
            (format "-----END ~a-----" label))))

(define pem-base64-line-trim : (-> Bytes Bytes)
  (lambda [line]
    (define maxidx : Fixnum (- (bytes-length line) 1))
    
    (let trim ([idx : Fixnum maxidx])
      (cond [(< idx 0) #""]
            [(< (bytes-ref line idx) #x2B) (trim (- idx 1))]
            [(= idx maxidx) line]
            [else (subbytes line 0 (+ idx 1))]))))

(define pem-encapsulation-label : (-> Bytes (Option Symbol))
  (lambda [line]
    (define maybe-label (regexp-match #px#"^\\s*[-]+(BEGIN|END) ([^-]+)[-]+\\s*$" line))
    
    (and (list? maybe-label)
         (string->symbol (format "~a" (car (reverse maybe-label)))))))

(define pem-label-equal? : (-> Symbol (Option Symbol) Boolean)
  (lambda [label LABEL]
    (and (symbol? LABEL)
         (or (eq? label LABEL)
             (let ([s (symbol->immutable-string label)]
                   [S (symbol->immutable-string LABEL)])
               (or (string-ci=? s S)
                   (string-ci=? (string-replace s "-" " ") S)))))))
