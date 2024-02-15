#lang racket/base

(provide (all-defined-out))

(require racket/path)
(require racket/port)
(require racket/format)
(require racket/pretty)

(require syntax/strip-context)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define std-read-syntax
  (lambda [src /dev/cin modname read-shell-script px.ext norm.ext]
    (regexp-match #px"^\\s*" /dev/cin) ; skip blanks before real c content

    (define-values (line column position) (port-next-location /dev/cin))
    (define bytes-bag (port->bytes /dev/cin))
    (define lang.λsh
      (cond [(path? src)
             (define src.λsh (path-replace-extension (file-name-from-path src) ""))
             (define path.λsh (if (regexp-match? px.ext src.λsh) src.λsh (path-replace-extension src.λsh norm.ext)))
             (string->symbol (path->string path.λsh))]
            [else '|this should not happen| 'lang.λsh]))
    
    (strip-context
     #`(module #,lang.λsh typed/racket/base
         (provide (all-from-out #,modname) #,lang.λsh)

         (require #,modname)

         (define-values (#,lang.λsh MB cpu real gc)
           (let ([/dev/rawin (open-input-bytes #,bytes-bag '#,src)]
                 [mem0 (current-memory-use)])
             (port-count-lines! /dev/rawin)
             (set-port-next-location! /dev/rawin #,line #,column #,position)
             (define-values (&lang.c cpu real gc) (time-apply #,read-shell-script (list /dev/rawin)))
             (values (car &lang.c) (/ (- (current-memory-use) mem0) 1024.0 1024.0) cpu real gc)))

         (module+ main
           (require racket/pretty)
           (require racket/format)
           
           (pretty-print-columns 160)

           (define benchmark : String
             (format "[~a]memory: ~aMB cpu time: ~a real time: ~a gc time: ~a"
                     '#,lang.λsh (~r MB #:precision '(= 3)) cpu real gc))
           
           (define drracket? : Boolean (regexp-match? #px"DrRacket$" (find-system-path 'run-file)))
           (if drracket? #,lang.λsh (printf "~a~n~a~n" (pretty-format #,lang.λsh) benchmark))
           (when drracket? (displayln benchmark)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define sh-read
  (lambda [[/dev/cin (current-input-port)]]
    (regexp-match #px"^\\s*" /dev/cin) ; skip blanks between `#lang` and contents
    (port->bytes /dev/cin)))

(define sh-read-syntax
  (lambda [[src #false] [/dev/cin (current-input-port)]]
    (std-read-syntax src /dev/cin 'shmon 'read-shmon-script #px"\\.λsh$" ".λsh")))

(define (sh-info in mod line col pos)
  (lambda [key default]
    (case key
      [(drracket:default-filters) '(["λsh Sources" "*.λsh"])]
      [(drracket:default-extension) "λsh"]
      ;[(color-lexer) (dynamic-require 'stdc/village/clang/lexer 'c-lexer)]
      [else default])))
