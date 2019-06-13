#lang typed/racket/base

(require typed/racket/unsafe)

(module unsafe racket/base
  (provide (all-defined-out))
  
  (require digimon/ffi)

  (define user-lib (digimon-ffi-lib "user"))

  (define-ffi-definer define-user user-lib)

  (define-user user_home_dir
    (_fun [name : _symbol]
          [buffer : _bytes = (make-bytes 1024)]
          [bsize : _size = (bytes-length buffer)]
          -> [dirsize : _ulong]
          -> (and (> dirsize 0)
                  (bytes->path (cond [(>= dirsize bsize) buffer]
                                     [else (subbytes buffer 0 dirsize)]))))))

(unsafe-require/typed/provide
 (submod "." unsafe)
 [user_home_dir (-> Symbol (Option Path))])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define user-home-dir : (case-> [-> (Option Path)]
                                [(Option Symbol) -> (Option Path)])
  (case-lambda
    [(username) (user_home_dir (or username '||))]
    [() (user_home_dir '||)]))

(user-home-dir)
(user-home-dir 'wargrey)
(user-home-dir 'root)
(user-home-dir 'Administrator)
