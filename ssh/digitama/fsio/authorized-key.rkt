#lang typed/racket/base

(provide (all-defined-out))

(require digimon/binscii)
(require digimon/filesystem)

(require "../diagnostics.rkt")
(require "../authentication/option.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(struct authorized-key
  ([type : Symbol]
   [raw : Bytes]
   [comment : (Option String)]
   [options : (Option SSH-Userauth-Option)])
  #:constructor-name make-authorized-key
  #:type-name Authorized-Key
  #:transparent)

(define predefined-keytypes : (Listof Symbol)
  (list 'ecdsa-sha2-nistp256 'ecdsa-sha2-nistp384 'ecdsa-sha2-nistp521 'ssh-ed25519 'ssh-dss 'ssh-rsa))

(define-file-reader read-authorized-keys #:+ (Immutable-HashTable Symbol (Listof Authorized-Key))
  (lambda [/dev/keyin]
    (define syek : (Listof Authorized-Key)
      (for/fold ([syek : (Listof Authorized-Key) null])
                ([key (in-port read-key-line /dev/keyin)])
        (if (exn? key) syek (cons key syek))))
    
    (for/fold ([keys : (Immutable-HashTable Symbol (Listof Authorized-Key)) (make-immutable-hasheq)])
              ([key : Authorized-Key (in-list syek)])
      (hash-set keys (authorized-key-type key)
                (cons key (hash-ref keys (authorized-key-type key)
                                    (λ [] null)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define read-key-line : (-> Input-Port (U Authorized-Key EOF exn))
  (lambda [/dev/keyin]
    (with-handlers ([exn:ssh:fsio? (λ [[e : exn:ssh:fsio]] (read-line /dev/keyin) e)])
      (let readline ([type : Symbol '||]
                     [key : (Option Bytes) #false]
                     [comment : (Option String) #false]
                     [option : (Option SSH-Userauth-Option) #false]
                     [this-char : (Option Char) #\space])
        (cond [(or (not this-char) (eq? this-char #\newline))
               (cond [(not key) (if (eq? this-char #\newline) (read-key-line /dev/keyin) eof)]
                     [else (make-authorized-key type key comment option)])]
              [(eq? type '||)
               (let-values ([(token maybe-char) (read-key-token /dev/keyin #\= #\space #\,)])
                 (define maybe-type : Symbol (string->symbol (string-downcase token)))
                 (cond [(memq maybe-type predefined-keytypes) (readline maybe-type key comment option maybe-char)]
                       [(and option) (discard-broken-key /dev/keyin "bad option")]
                       [else (let-values ([(option separator) (read-key-options /dev/keyin maybe-type maybe-char)])
                               (readline type key comment option separator))]))]
              [(not key)
               (let-values ([(token maybe-char) (read-key-token /dev/keyin #\space)])
                 (readline type (base64-decode token) comment option maybe-char))]
              [else ; maybe comment
               (let-values ([(token maybe-char) (read-key-token /dev/keyin)])
                 (readline type key (and (not (string=? token "")) token) option maybe-char))])))))

(define read-key-options : (-> Input-Port Symbol (Option Char) (Values SSH-Userauth-Option (Option Char)))
  (lambda [/dev/keyin leading-sym this-char]
    (let read-option ([flags : (Listof Symbol) null]
                      [parameters : (Listof (Pairof Symbol String)) null]
                      [sym : Symbol leading-sym]
                      [ch : (Option Char) this-char])
      (cond [(eq? ch #\,)
             (let-values ([(token maybe-char) (read-key-token /dev/keyin #\= #\space #\,)])
               (read-option (if (eq? sym '||) flags (cons sym flags))
                            parameters (string->symbol token) maybe-char))]
            [(eq? ch #\=)
             (cond [(eq? sym '||) (discard-broken-key /dev/keyin "lack option name")]
                   [else (let-values ([(value maybe-char) (read-key-token /dev/keyin #\space #\,)])
                           (read-option flags (cons (cons sym value) parameters) '|| maybe-char))])]
            [else ; (memq ch '(#false #\newline #\space))
             (values (make-ssh-userauth-option #:flags (reverse flags) #:parameters (reverse parameters))
                     ch)]))))

(define read-key-token : (-> Input-Port Char * (Values String (Option Char)))
  (lambda [/dev/keyin . terminators]
    (let read-token ([srahc : (Listof Char) null]
                     [boundary : Boolean #false]
                     [ch : (Option Char) (read-key-char /dev/keyin)])
      (cond [(or (not ch) (eq? ch #\newline)) (values (key-srahc->token srahc) ch)]
            [(memq ch terminators) (values (key-srahc->token srahc) ch)]
            [(and boundary) (discard-broken-key /dev/keyin "bad quotes")]
            [(not (eq? ch #\")) (read-token (cons ch srahc) boundary (read-key-char /dev/keyin))]
            [(pair? srahc) (discard-broken-key /dev/keyin "bad quotes")]
            [else (let-values ([(gnirts nch) (read-key-string /dev/keyin)])
                    (read-token gnirts #true nch))]))))

(define read-key-string : (-> Input-Port (Values (Listof Char) (Option Char)))
  (lambda [/dev/keyin]
    (let read-string ([srahc : (Listof Char) null]
                      [escaping : Boolean #false])
      (define ch : (Option Char) (read-key-char /dev/keyin))

      (cond [(not ch) (values srahc ch)]
            [(and escaping) (read-string (cons ch srahc) #false)]
            [(eq? ch #\\) (read-string srahc #true)]
            [(eq? ch #\") (values srahc (read-key-char /dev/keyin))]
            [(eq? ch #\newline) (values srahc ch)]
            [else (read-string (cons ch srahc) escaping)]))))

(define read-key-char : (-> Input-Port (Option Char))
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

(define discard-broken-key : (-> Input-Port String Any * Nothing)
  (lambda [/dev/keyin errfmt . messages]
    (apply ssh-raise-syntax-error read-key-line /dev/keyin errfmt messages)))

(define key-srahc->token : (-> (Listof Char) String)
  (lambda [srahc]
    (cond [(null? srahc) ""]
          [else (list->string (reverse srahc))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define src (build-path (find-system-path 'home-dir) "Racket" "lambda-shell" "ssh" "tamer" "stone" "authorized_keys"))
(read-authorized-keys* src #:count-lines? #true)
