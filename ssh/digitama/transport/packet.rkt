#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out) ~size)

(require racket/unsafe/ops)

(require digimon/format)

(require "../stdin.rkt")
(require "../datatype.rkt")
(require "../diagnostics.rkt")
(require "../assignment.rkt")

#|
 uint32    packet_length  (the next 3 fields)               -
 byte      padding_length (in the range of [4, 255])         \ the size of these 4 fields should be multiple of
 byte[n1]  payload; n1 = packet_length - padding_length - 1  / 8 or cipher-blocksize whichever is larger
 byte[n2]  random padding; n2 = padding_length              -
 byte[m]   mac (Message Authentication Code - MAC); m = mac_length
|#

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-binary-packet : (-> Output-Port Bytes Byte Index Byte Nonnegative-Fixnum)
  (lambda [/dev/tcpout payload cipher-blocksize payload-capacity mac-length]
    (define payload-length : Index (bytes-length payload))

    ;; NOTE: we do not forbid the overloaded packet since we do not know the payload capacity that the peer holds.
    (when (> payload-length payload-capacity)
      (ssh-log-message 'debug "packet may overload based on local preference(~a > ~a), nonetheless, the peer may hold a much larger capacity"
                       (~size payload-length) (~size payload-capacity)))

    (define-values (packet-length padding-length) (resolve-package-length payload-length cipher-blocksize))
    (define packet : Bytes (bytes-append (ssh-uint32->bytes packet-length) (bytes padding-length) payload (ssh-cookie padding-length)))

    (define sent : Nonnegative-Fixnum
      (+ (write-bytes packet /dev/tcpout)
         mac-length))
    
    (flush-output /dev/tcpout)

    sent))

(define ssh-read-binary-packet : (-> Input-Port Index Byte (Values Bytes Bytes Nonnegative-Fixnum))
  (lambda [/dev/tcpin payload-capacity mac-length]
    (define length-bs : Bytes (ssh-read-bytes /dev/tcpin 4))
    (define packet-capacity : Nonnegative-Fixnum (+ payload-capacity 4))
    (define-values (packet-length _) (ssh-bytes->uint32 length-bs))

    (when (> packet-length packet-capacity)
      (throw exn:ssh:defense /dev/tcpin 'read-binary-packet
             "packet overlength: ~a > ~a"
             (~size packet-length) (~size packet-capacity)))

    (define padded-payload : Bytes (ssh-read-bytes /dev/tcpin packet-length))
    (define padding-length : Byte (bytes-ref padded-payload 0))
    (define payload-end : Fixnum (- packet-length padding-length))

    (when (< payload-end 1)
      (throw exn:ssh:defense /dev/tcpin 'read-binary-packet
             "invalid payload length: ~a" (unsafe-fx- payload-end 1)))

    (values (subbytes padded-payload 1 payload-end)
            (cond [(> mac-length 0) (ssh-read-bytes /dev/tcpin mac-length)]
                  [else #""])
            (+ packet-length mac-length 4))))

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
