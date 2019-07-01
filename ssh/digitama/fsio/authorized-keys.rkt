#lang typed/racket/base

(provide (all-defined-out))

(require digimon/binscii)
(require digimon/filesystem)

(require "../authentication/datatype.rkt")
(require "../algorithm/fingerprint.rkt")

(require "../diagnostics.rkt")
(require "../assignment.rkt")
(require "../../datatype.rkt")

(define ssh-multiple-options : (Listof Symbol) (list 'environment 'permitlisten 'permitopen))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct authorized-key
  ([type : Symbol]
   [raw : Bytes]
   [fingerprint : String]
   [comment : (Option String)]
   [options : (Option SSH-Userauth-Option)])
  #:constructor-name make-authorized-key
  #:type-name Authorized-Key
  #:transparent)

(define-file-reader read-authorized-keys #:+ (Immutable-HashTable Symbol (Listof Authorized-Key))
  (lambda [/dev/keyin]
    (define syek : (Listof Authorized-Key)
      (for/fold ([syek : (Listof Authorized-Key) null])
                ([key (in-port ssh-read-key-line /dev/keyin)])
        (if (exn? key) syek (cons key syek))))
    
    (for/fold ([keys : (Immutable-HashTable Symbol (Listof Authorized-Key)) (make-immutable-hasheq)])
              ([key : Authorized-Key (in-list syek)])
      (hash-set keys (authorized-key-type key)
                (cons key (hash-ref keys (authorized-key-type key)
                                    (λ [] null)))))))

(define authorized-key-ref : (-> (Immutable-HashTable Symbol (Listof Authorized-Key)) Symbol Bytes (Option Authorized-Key))
  (lambda [key-database keytype key]
    (let ref ([keys : (Listof Authorized-Key) (hash-ref key-database keytype (λ [] null))])
      (and (pair? keys)
           (let ([k (car keys)])
             (or (and (bytes=? (authorized-key-raw k) key) k)
                 (ref (cdr keys))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-read-key-line : (-> Input-Port (U Authorized-Key EOF exn))
  (lambda [/dev/keyin]
    (define public-keytypes : (Listof Symbol) (ssh-names->namelist (ssh-hostkey-algorithms)))
    (with-handlers ([exn:ssh:fsio? (λ [[e : exn:ssh:fsio]] (read-line /dev/keyin) e)])
      (let readline ([type : Symbol '||]
                     [key : (Option Bytes) #false]
                     [comment : (Option String) #false]
                     [option : (Option SSH-Userauth-Option) #false]
                     [this-char : (Option Char) #\space])
        (cond [(or (not this-char) (eq? this-char #\newline))
               (cond [(not key) (if (eq? this-char #\newline) (ssh-read-key-line /dev/keyin) eof)]
                     [else (make-authorized-key type (base64-decode key)
                                                (ssh-key-fingerprint type key #:hash sha256-bytes #:digest base64-encode)
                                                comment option)])]
              [(eq? type '||)
               (let-values ([(token maybe-char) (ssh-read-key-token /dev/keyin #\= #\space #\,)])
                 (define maybe-type : Symbol (string->symbol (string-downcase token)))
                 (cond [(memq maybe-type public-keytypes) (readline maybe-type key comment option maybe-char)]
                       [(and option) (discard-broken-key ssh-read-key-line /dev/keyin "bad option")]
                       [else (let-values ([(option separator) (ssh-read-key-options /dev/keyin maybe-type maybe-char)])
                               (readline type key comment option separator))]))]
              [(not key)
               (let-values ([(token maybe-char) (ssh-read-key-token /dev/keyin #\space)])
                 (readline type (string->bytes/utf-8 token) comment option maybe-char))]
              [else ; maybe comment
               (let-values ([(token maybe-char) (ssh-read-key-token /dev/keyin)])
                 (readline type key (and (not (string=? token "")) token) option maybe-char))])))))

(define ssh-read-key-options : (-> Input-Port Symbol (Option Char) (Values SSH-Userauth-Option (Option Char)))
  (lambda [/dev/keyin leading-sym this-char]
    (let read-option ([sgalf : (Listof Symbol) null]
                      [sretemarap : (Listof (Pairof Symbol (List String (Option Natural) (Option Natural)))) null]
                      [sym : Symbol leading-sym]
                      [ch : (Option Char) this-char])
      (cond [(eq? ch #\,)
             (let-values ([(token maybe-char) (ssh-read-key-token /dev/keyin #\= #\space #\,)])
               (read-option (if (eq? sym '||) sgalf (cons sym sgalf))
                            sretemarap (string->symbol token) maybe-char))]
            [(eq? ch #\=)
             (let-values ([(line col _) (port-next-location /dev/keyin)])
               (when (and (assq sym sretemarap) (not (memq sym ssh-multiple-options)))
                 (discard-broken-key ssh-read-key-options /dev/keyin "multiple '~a' clauses" sym))
               (cond [(eq? sym '||) (discard-broken-key ssh-read-key-options /dev/keyin "lack option name")]
                     [else (let-values ([(value maybe-char) (ssh-read-key-token /dev/keyin #\space #\,)])
                             (define this-parameter : (Pairof Symbol (List String (Option Natural) (Option Natural)))
                               (cons sym (list value line (and col (+ col 1)))))
                             (read-option sgalf (cons this-parameter sretemarap) '|| maybe-char))]))]
            [else ; (memq ch '(#false #\newline #\space))
             (let ([flags (reverse (if (eq? sym '||) sgalf (cons sym sgalf)))])
               (values (make-ssh-userauth-option #:flags flags #:parameters (reverse sretemarap) #:source (object-name /dev/keyin))
                       ch))]))))

(define ssh-read-key-token : (-> Input-Port Char * (Values String (Option Char)))
  (lambda [/dev/keyin . terminators]
    (let read-token ([srahc : (Listof Char) null]
                     [boundary : Boolean #false]
                     [ch : (Option Char) (ssh-read-key-char /dev/keyin)])
      (cond [(or (not ch) (eq? ch #\newline)) (values (key-srahc->token srahc) ch)]
            [(memq ch terminators) (values (key-srahc->token srahc) ch)]
            [(and boundary) (discard-broken-key ssh-read-key-token /dev/keyin "bad quotes")]
            [(not (eq? ch #\")) (read-token (cons ch srahc) boundary (ssh-read-key-char /dev/keyin))]
            [(pair? srahc) (discard-broken-key ssh-read-key-token /dev/keyin "bad quotes")]
            [else (let-values ([(gnirts nch) (ssh-read-key-string /dev/keyin)])
                    (read-token gnirts #true nch))]))))

(define ssh-read-key-string : (-> Input-Port (Values (Listof Char) (Option Char)))
  (lambda [/dev/keyin]
    (let read-string ([srahc : (Listof Char) null]
                      [escaping : Boolean #false])
      (define ch : (Option Char) (ssh-read-key-char /dev/keyin))

      (cond [(not ch) (values srahc ch)]
            [(and escaping) (read-string (cons ch srahc) #false)]
            [(eq? ch #\\) (read-string srahc #true)]
            [(eq? ch #\") (values srahc (ssh-read-key-char /dev/keyin))]
            [(eq? ch #\newline) (values srahc ch)]
            [else (read-string (cons ch srahc) escaping)]))))

(define ssh-read-key-char : (-> Input-Port (Option Char))
  (lambda [/dev/keyin]
    (define ch : (U Char EOF) (read-char /dev/keyin))
    (cond [(eof-object? ch) #false]
          [(not (char-whitespace? ch)) (if (eq? ch #\#) (discard-comments /dev/keyin) ch)]
          [(or (eq? ch #\return) (eq? ch #\linefeed)) (discard-newline /dev/keyin)]
          [else (let skip-blanks ([count : Natural 0])
                  (define nch : (U Char EOF) (peek-char /dev/keyin count))
                  (cond [(eof-object? nch) (discard-spaces /dev/keyin count #false)]
                        [(not (char-whitespace? nch)) (if (eq? nch #\#) (discard-comments /dev/keyin) (discard-spaces /dev/keyin count #false))]
                        [(or (eq? nch #\return) (eq? nch #\linefeed)) (discard-spaces /dev/keyin (+ count 1) #true)]
                        [else (skip-blanks (+ count 1))]))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define discard-newline : (-> Input-Port Char)
  (lambda [/dev/keyin]
    (define next-char : (U Char EOF) (peek-char /dev/keyin))
    (when (or (eq? next-char #\linefeed) (eq? next-char #\return))
      (read-char /dev/keyin))
    #\newline))

(define discard-spaces : (-> Input-Port Natural Boolean Char)
  (lambda [/dev/keyin count newline?]
    (cond [(> count 1) (read-string count /dev/keyin)]
          [(= count 1) (read-char /dev/keyin)])
    (cond [(not newline?) #\space]
          [else (discard-newline /dev/keyin)])))

(define discard-comments : (-> Input-Port Char)
  (lambda [/dev/keyin]
    (read-line /dev/keyin)
    #\newline))

(define discard-broken-key : (-> Any Input-Port String Any * Nothing)
  (lambda [func /dev/keyin errfmt . messages]
    (define-values (line col _) (port-next-location /dev/keyin))

    (apply ssh-raise-syntax-error func (object-name /dev/keyin) line col errfmt messages)))

(define key-srahc->token : (-> (Listof Char) String)
  (lambda [srahc]
    (cond [(null? srahc) ""]
          [else (list->string (reverse srahc))])))
