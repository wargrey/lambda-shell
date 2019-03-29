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
  ([format : Symbol 'ssh-rsa]
   [e : Integer]
   [n : Integer]))

(call-with-input-file* known_hosts
  (λ [[/dev/sshin : Input-Port]]
    (filter ssh-rsa? (for/list : (Listof Any) ([host (in-lines /dev/sshin)])
                      (define record : (Listof String) (string-split host))
                      (when (string=? (cadr record) "ssh-rsa")
                        (define ssh-rsa-raw : Bytes (base64-decode (caddr record)))
                        (define-values (rsa end-index) (bytes->ssh-rsa ssh-rsa-raw))
                        (and (= (bytes-length ssh-rsa-raw) end-index)
                             rsa))))))

(newline)


(define rsa-raw : Bytes (base64-decode "AAAAB3NzaC1yc2EAAAADAQABAAABAQDRdm4dv0SziihHSttMwWaUMVFXpc91oDfI0ToVmmbmy57j6xZy4R0RAfrg/G1kD18+VX/tfmV+dpH6av6MuMFueHk0Q/fhNMlQxf4By7bNdgLXKFGhXnO+jfesHZs32SUQ/fRMvHH+KyDPAJm5+LGTPQqYfQ+tUmSrmootGDBa+i+5AB4+aVnYGsmzoYwddzmXTIGAzPBuEYTwiEDa/y58fLRhZvBp2W0/qlHHKejcBxWHkIUPvp9eTE1qT4hkq98G1cCvKoHelKNP0uAEIEeFXRrm915AsAlkDpFlIqDfP5gTkoWsLHEXJjJ0uuXgAOhtF36dSm/kHWJt1YBsKRar"))

(bytes->ssh-rsa rsa-raw)
(bytes-length rsa-raw)