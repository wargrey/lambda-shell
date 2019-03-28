#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6.6
;;; https://tools.ietf.org/html/rfc8268

(provide (all-defined-out))

(require racket/string)

(require digimon/binscii)

(require "../../datatype.rkt")

(define .ssh : Path (build-path (find-system-path 'home-dir) ".ssh"))
(define known_hosts : Path (build-path .ssh "known_hosts"))

(define-ssh-struct ssh-rsa : SSH-RSA
  ([format : String "ssh-rsa"]
   [e : Integer]
   [n : Integer]))

(call-with-input-file* known_hosts
  (λ [[/dev/sshin : Input-Port]]
    (filter ssh-rsa? (for/list : (Listof Any) ([host (in-lines /dev/sshin)])
                      (define record : (Listof String) (string-split host))
                      (when (string=? (cadr record) "ssh-rsa")
                        (define ssh-ras-raw : Bytes (base64-decode (string->bytes/utf-8 (caddr record))))
                        (bytes->ssh-rsa ssh-ras-raw))))))
