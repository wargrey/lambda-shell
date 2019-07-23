#lang typed/racket/base

(provide (all-defined-out))

(require racket/string)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define scp-file-path : (-> String Index (Values Symbol (Option String) Index Path-String))
  (lambda [remote-path port]
    (cond [(string-prefix? remote-path "scp://") (scp-protocol-path remote-path port)]
          [(not (string-contains? remote-path ":")) (values (current-username) #false port remote-path)]
          [else (let* ([tokens (string-split remote-path ":")]
                       [hosts (string-split (car tokens) "@")])
                  (define path : String
                    (let ([p (string-join (cdr tokens) ":")])
                      (cond [(> (string-length p) 0) p]
                            [else "."])))

                  (case (length hosts)
                    [(2) (values (string->symbol (car hosts)) (cadr hosts) port path)]
                    [(1) (values (current-username) (car hosts) port path)]
                    [else (error 'scp-file-path "invalid path: ~a" remote-path)]))])))

(define scp-protocol-path : (-> String Index (Values Symbol String Index Path-String))
  (lambda [scp://host/path fallback-port]
    (define host/path : String (substring scp://host/path 6))
    (define tokens : (Listof String) (string-split host/path "/"))
    (define ports : (Listof String) (string-split (car tokens) ":"))
    (define hosts : (Listof String) (string-split (car ports) "@"))
    
    (define path : String
      (let ([p (string-join (cdr tokens) "/")])
        (cond [(string=? p "") "."]
              [else p])))

    (define port : Index
      (let ([p (case (length ports)
                 [(2) (or (string->number (cadr ports)) (error 'scp-protocol-path "invalid port: ~a" scp://host/path))]
                 [(1) fallback-port]
                 [else (error 'scp-protocol-path "invalid port: ~a" scp://host/path)])])
        (cond [(and (index? p) (<= 1 p 65535)) p]
              [else (error 'scp-protocol-path "invalid port: ~a" p)])))
    
    (case (length hosts)
      [(2) (values (string->symbol (car hosts)) (cadr hosts) port path)]
      [(1) (values (current-username) (car hosts) port path)]
      [else (error 'scp-protocol-path "invalid path: ~a" scp://host/path)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define current-username : (-> Symbol)
  (lambda []
    (define-values (base name dir?) (split-path (find-system-path 'home-dir)))

    (cond [(symbol? name) 'root #| should not happen |#]
          [else (string->symbol (path->string name))])))
