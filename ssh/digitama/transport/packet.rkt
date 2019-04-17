#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out) ~size)

(require digimon/format)

(require "../../datatype.rkt")
(require "../diagnostics.rkt")

(require "../algorithm/random.rkt")

#|
 uint32    packet_length  (the next 3 fields)               -
 byte      padding_length (in the range of [4, 255])         \ the size of these 4 fields should be multiple of
 byte[n1]  payload; n1 = packet_length - padding_length - 1  / 8 or cipher-blocksize whichever is larger
 byte[n2]  random padding; n2 = padding_length              -
 byte[m]   mac (Message Authentication Code - MAC); m = mac_length
|#

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-write-binary-packet : (->* (Output-Port Bytes Index Byte)
                                       ((Option (-> Bytes Bytes)) (-> Bytes Bytes) (Option (-> Bytes Bytes)))
                                       Nonnegative-Fixnum)
  (lambda [/dev/tcpout payload-raw payload-capacity cipher-blocksize [maybe-inflate #false] [encrypt values] [maybe-mac #false]]
    (define payload : Bytes (if maybe-inflate (maybe-inflate payload-raw) payload-raw))
    (define payload-length : Index (bytes-length payload))

    ;; NOTE: we do not forbid the overloaded packet since we do not know the payload capacity that the peer holds.
    (when (> payload-length payload-capacity)
      (ssh-log-message 'debug "packet may overload based on local preference(~a > ~a), nonetheless, the peer may hold a much larger capacity"
                       (~size payload-length) (~size payload-capacity)))

    (define-values (packet-length padding-length) (resolve-package-length payload-length cipher-blocksize))
    (define packet-raw : Bytes (bytes-append (ssh-uint32->bytes packet-length) (bytes padding-length) payload (ssh-cookie padding-length)))
    (define packet : Bytes (encrypt packet-raw))
    (define digest : Bytes (if maybe-mac (maybe-mac packet-raw) #""))

    (define sent : Nonnegative-Fixnum
      (+ (write-bytes packet /dev/tcpout)
         (write-bytes digest /dev/tcpout)))
    
    (flush-output /dev/tcpout)

    sent))

(define ssh-read-binary-packet : (case-> [Input-Port Index -> (Values Bytes Nonnegative-Fixnum)]
                                         [Input-Port Index (Option (-> Bytes Bytes)) (-> Bytes Byte) (-> Bytes Bytes) -> (Values Bytes Nonnegative-Fixnum)])
  (case-lambda
    [(/dev/tcpin payload-capacity)
     (ssh-read-plain-packet /dev/tcpin payload-capacity)]
    [(/dev/tcpin payload-capacity maybe-deflate decrypt mac)
     (ssh-read-cipher-packet /dev/tcpin payload-capacity maybe-deflate decrypt mac)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-read-plain-packet : (-> Input-Port Index (Values Bytes Nonnegative-Fixnum))
  (lambda [/dev/tcpin payload-capacity]
    (define length-bs : Bytes (ssh-read-bytes /dev/tcpin 4 ssh-read-plain-packet))
    (define packet-capacity : Nonnegative-Fixnum (+ payload-capacity 4))
    (define-values (packet-length _) (ssh-bytes->uint32 length-bs))

    (when (> packet-length packet-capacity)
      (ssh-raise-defence-error ssh-read-plain-packet
                               "packet overlength: ~a > ~a"
                               (~size packet-length) (~size packet-capacity)))

    (define padded-payload : Bytes (ssh-read-bytes /dev/tcpin packet-length ssh-read-plain-packet))
    (define padding-length : Byte (bytes-ref padded-payload 0))
    (define payload-end : Fixnum (- packet-length padding-length))

    (when (< payload-end 1)
      (ssh-raise-defence-error ssh-read-plain-packet
                               "invalid payload length: ~a" (- payload-end 1)))

    (values (subbytes padded-payload 1 payload-end)
            (+ packet-length 4))))

(define ssh-read-cipher-packet : (-> Input-Port Index (Option (-> Bytes Bytes)) (-> Bytes Byte) (-> Bytes Bytes) (Values Bytes Nonnegative-Fixnum))
  (lambda [/dev/tcpin payload-capacity maybe-deflate decrypt mac]
    (define length-bs : Bytes (ssh-read-bytes /dev/tcpin 4 ssh-read-cipher-packet))
    (define packet-capacity : Nonnegative-Fixnum (+ payload-capacity 4))
    (define-values (packet-length _) (ssh-bytes->uint32 length-bs))

    (when (> packet-length packet-capacity)
      (ssh-raise-defence-error ssh-read-cipher-packet
                               "packet overlength: ~a > ~a"
                               (~size packet-length) (~size packet-capacity)))

    (define padded-payload : Bytes (ssh-read-bytes /dev/tcpin packet-length ssh-read-cipher-packet))
    (define padding-length : Byte (bytes-ref padded-payload 0))
    (define payload-end : Fixnum (- packet-length padding-length))

    (when (< payload-end 1)
      (ssh-raise-defence-error ssh-read-cipher-packet
                               "invalid payload length: ~a" (- payload-end 1)))

    (define payload : Bytes (subbytes padded-payload 1 payload-end))
    
    #;(cond [(not maybe-mac) (ssh-read-bytes /dev/tcpin mac-length)]
            [else #""])
    
    (values (if maybe-deflate (maybe-deflate payload) payload)
            (+ packet-length #;mac-length 4))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define resolve-package-length : (-> Index Byte (Values Index Byte))
  (lambda [payload-length cipher-blocksize]
    (let* ([idsize : Byte (max cipher-blocksize 8)]
           [packet-draft (+ 4 1 payload-length)]
           [padding-draft (- idsize (remainder packet-draft idsize))]
           [padding-draft (if (< padding-draft 4) (+ padding-draft idsize) padding-draft)]
           [thwarting-capacity (quotient (- #xFF padding-draft) idsize)]
           [random-length (+ padding-draft (* idsize (random (+ thwarting-capacity 1))))])
      (values (assert (- (+ packet-draft random-length) 4) index?)
              (assert random-length byte?)))))

(define ssh-read-bytes : (-> Input-Port Integer Procedure Bytes)
  (lambda [/dev/sshin amt func]
    (define bs : (U Bytes EOF) (read-bytes amt /dev/sshin))
    (cond [(eof-object? bs) (ssh-raise-eof-error func "connection lost")]
          [else bs])))
