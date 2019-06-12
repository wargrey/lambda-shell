#lang racket/base

(require digimon/ffi)

(define user-lib (digimon-ffi-lib "user"))

(define-ffi-definer define-user user-lib)

(define-user user_home_dir
  (_fun #:save-errno 'posix
        [name : _symbol]
        [buffer : _bytes = (make-bytes 1024)]
        [bsize : _size = (bytes-length buffer)]
        -> [dirsize : _ulong]
        -> (and (> dirsize 0)
                (bytes->path (cond [(= dirsize bsize) buffer]
                                   [else (subbytes buffer 0 dirsize)])))))

(user_home_dir 'wargrey)
(user_home_dir 'root)
(user_home_dir 'tamer)
