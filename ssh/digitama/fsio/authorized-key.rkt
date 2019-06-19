#lang typed/racket/base

(provide (all-defined-out))

(require racket/string)
(require racket/sequence)

(require digimon/binscii)
(require digimon/filesystem)

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
  (list 'ecdsa-sha2-nistp256 'ecdsa-sha2-nistp384 'ecdsa-sha2-nistp521 'ssh-ed25519 'ssh-dss 'ssh-rsa
        '|| #| the false key type indicator |#))

(define-file-loader read-authorized-keys #:+ (Immutable-HashTable Symbol (Listof Authorized-Key))
  (lambda [/dev/keyin]
    (define syek : (Listof Authorized-Key) (reverse (sequence->list (in-port read-key-line /dev/keyin))))
    (for/fold ([keys : (Immutable-HashTable Symbol (Listof Authorized-Key)) (make-immutable-hasheq)])
              ([key : Authorized-Key (in-list syek)])
      (hash-set keys (authorized-key-type key)
                (cons key (hash-ref keys (authorized-key-type key)
                                    (λ [] null)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define read-key-line : (-> Input-Port (U Authorized-Key EOF))
  (lambda [/dev/keyin]
    (let readline ([type : Symbol '||]
                   [key : (Option Bytes) #false]
                   [comment : (Option String) #false]
                   [command : (Option String) #false]
                   [options : (Listof Symbol) null]
                   [envs : (Listof (Pairof String String)) null]
                   [ch : (Option Char) #\space])
      (cond [(or (not ch) (eq? ch #\newline))
             (cond [(not key) (if (eq? ch #\newline) (read-key-line /dev/keyin) eof)]
                   [else (make-authorized-key type key comment
                                              (make-ssh-userauth-option #:flags options
                                                                        #:environments envs
                                                                        #:command command))])]
            [(eq? type '||)
             (let-values ([(token maybe-char) (read-key-token /dev/keyin #\= #\space #\,)])
               (define kw : Symbol (string->symbol (string-downcase token)))
               (cond [(memq kw predefined-keytypes) (readline kw key comment command options envs maybe-char)]
                     [else (readline type key comment command (cons kw options) envs maybe-char)]))]
            [(not key)
             (let-values ([(token maybe-char) (read-key-token /dev/keyin #\space)])
               (readline type (base64-decode token) comment command options envs maybe-char))]
            [else (let-values ([(token maybe-char) (read-key-token /dev/keyin)])
                    (readline type key (and (not (string=? token "")) token)
                              command options envs maybe-char))]))))

(define read-key-token : (-> Input-Port Char * (Values String (Option Char)))
  (lambda [/dev/keyin . terminators]
    (let read-token ([srahc : (Listof Char) null])
      (define ch : (Option Char) (read-key-char /dev/keyin))

      (cond [(or (not ch) (eq? ch #\newline)) (values (key-srahc->token srahc) ch)]
            [(memq ch terminators) (values (key-srahc->token srahc) ch)]
            [else (read-token (cons ch srahc))]))))

(define read-key-char : (-> Input-Port (Option Char))
  (lambda [/dev/keyin]
    (define ch : (U Char EOF) (read-char /dev/keyin))
    (cond [(eof-object? ch) #false]
          [(not (char-whitespace? ch)) (if (eq? ch #\#) (read-comment-rest /dev/keyin) ch)]
          [(or (eq? ch #\return) (eq? ch #\linefeed)) (read-newline-rest /dev/keyin)]
          [else (let skip-blanks ([count : Natural 0])
                  (define nch : (U Char EOF) (peek-char /dev/keyin count))
                  (cond [(eof-object? nch) (read-space-rest /dev/keyin count #false)]
                        [(not (char-whitespace? nch)) (if (eq? nch #\#) (read-comment-rest /dev/keyin) (read-space-rest /dev/keyin count #false))]
                        [(or (eq? nch #\return) (eq? nch #\linefeed)) (read-space-rest /dev/keyin (+ count 1) #true)]
                        [else (skip-blanks (+ count 1))]))])))

(define read-newline-rest : (-> Input-Port Char)
  (lambda [/dev/keyin]
    (define next-char : (U Char EOF) (peek-char /dev/keyin))
    (when (or (eq? next-char #\linefeed) (eq? next-char #\return))
      (read-char /dev/keyin))
    #\newline))

(define read-space-rest : (-> Input-Port Natural Boolean Char)
  (lambda [/dev/keyin count newline?]
    (cond [(> count 1) (read-string count /dev/keyin)]
          [(= count 1) (read-char /dev/keyin)])
    (cond [(not newline?) #\space]
          [else (read-newline-rest /dev/keyin)])))

(define read-comment-rest : (-> Input-Port Char)
  (lambda [/dev/keyin]
    (read-line /dev/keyin)
    #\newline))

(define key-srahc->token : (-> (Listof Char) String)
  (lambda [srahc]
    (cond [(null? srahc) ""]
          [else (list->string (reverse srahc))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define src (build-path (find-system-path 'home-dir) "Racket" "lambda-shell" "ssh" "tamer" "stone" "authorized_keys"))
(read-authorized-keys* src)
