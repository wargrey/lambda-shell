#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

(require racket/unsafe/ops)

(require "../stdin.rkt")
(require "../datatype.rkt")
(require "../exception.rkt")
(require "../assignment.rkt")

(define SSH-LONGEST-PAYLOAD-LENGTH : Positive-Index 32768)

#| uint32    packet_length  (the next 3 fields)               -
   byte      padding_length (in the range of [4, 255])         \ the size of these 4 fields should be multiple of
   byte[n1]  payload; n1 = packet_length - padding_length - 1  / 8 or cipher-blocksize whichever is larger
   byte[n2]  random padding; n2 = padding_length              -
   byte[m]   mac (Message Authentication Code - MAC); m = mac_length |#

(define ssh-write-binary-packet : (-> Output-Port Bytes Byte Void)
  (lambda [/dev/sshout payload cipher-blocksize]
    (define payload-length : Index (bytes-length payload))

    (when (> payload-length SSH-LONGEST-PAYLOAD-LENGTH)
      (throw exn:ssh:defense /dev/sshout 'write-binary-packet
             "packet overload: ~a; message: ~a"
             payload-length (ssh-message-number->name (bytes-ref payload 0))))

    (define-values (packet-length padding-length) (resolve-package-length payload-length cipher-blocksize))
    (define packet : Bytes (bytes-append (ssh-uint32->bytes packet-length) (bytes padding-length) payload (ssh-cookie padding-length)))
    (define padding-idx0 : Fixnum (- (bytes-length packet) padding-length))

    (write-bytes packet /dev/sshout)
    (flush-output /dev/sshout)))

(define ssh-read-binary-packet : (-> Input-Port Byte (Values Bytes Bytes))
  (lambda [/dev/sshin mac-length]
    (define length-bs : Bytes (ssh-read-bytes /dev/sshin 4))
    (define-values (packet-length _) (ssh-bytes->uint32 length-bs))

    ; 35000 is useless since it is much larger than the SSH-LONGEST-PAYLOAD-LENGTH
    (when (> packet-length (+ SSH-LONGEST-PAYLOAD-LENGTH 255 1))
      (throw exn:ssh:defense /dev/sshin 'read-binary-packet
             "packet overlength: ~a" packet-length))

    (define padded-payload : Bytes (ssh-read-bytes /dev/sshin packet-length))
    (define padding-length : Byte (bytes-ref padded-payload 0))
    (define payload-end : Fixnum (- packet-length padding-length))

    (when (< payload-end 1)
      (throw exn:ssh:defense /dev/sshin 'read-binary-packet
             "invalid payload length: ~a" (unsafe-fx- payload-end 1)))

    (values (subbytes padded-payload 1 payload-end)
            (cond [(= mac-length 0) (subbytes padded-payload payload-end)]
                  [else (ssh-read-bytes /dev/sshin mac-length)]))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define resolve-package-length : (-> Index Byte (Values Index Byte))
  (lambda [payload-length cipher-blocksize]
    (let* ([idsize : Byte (max cipher-blocksize 8)]
           [packet-draft (+ 4 1 payload-length)]
           [padding-draft (unsafe-fx- idsize (remainder packet-draft idsize))]
           [padding-draft (if (< padding-draft 4) (unsafe-fx+ padding-draft idsize) padding-draft)]
           [thwarting-capacity (unsafe-fxquotient (unsafe-fx- #xFF padding-draft) idsize)]
           [random-length (unsafe-fx+ padding-draft (unsafe-fx* idsize (random (unsafe-fx+ thwarting-capacity 1))))])
      (values (assert (unsafe-fx- (unsafe-fx+ packet-draft random-length) 4) index?)
              (assert random-length byte?)))))
