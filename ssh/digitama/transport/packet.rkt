#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

(require digimon/number)
(require digimon/format)

(require "../../message.rkt")
(require "../../datatype.rkt")
(require "../diagnostics.rkt")

#|
 uint32    packet_sequence_number ([0, #xFFFFFFFF], never reset, cyclic, not sent over the wire)
 
 uint32    packet_length  (the next 3 fields)               -
 byte      padding_length (in the range of [4, 255])         \ the size of these 4 fields should be multiple of
 byte[n1]  payload; n1 = packet_length - padding_length - 1  / 8 or cipher-blocksize whichever is larger
 byte[n2]  random padding; n2 = padding_length              -
 byte[m]   mac (Message Authentication Code - MAC); m = mac_length
|#

(define ssh-packet-size-index : 4 4)
(define ssh-packet-padding-size-index : 8 8)
(define ssh-packet-payload-index : 9 9)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-read-plain-packet : (-> Input-Port Bytes Index (Values Positive-Fixnum Positive-Fixnum))
  (lambda [/dev/tcpin parcel payload-capacity]
    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-size-index ssh-packet-payload-index ssh-read-plain-packet)

    (define-values (packet-length _) (ssh-bytes->uint32 parcel ssh-packet-size-index))
    (define padding-length : Byte (bytes-ref parcel ssh-packet-padding-size-index))
    (define payload-length : Index (ssh-incoming-payload-size packet-length padding-length payload-capacity ssh-read-plain-packet))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-payload-index packet-end ssh-read-plain-packet)
    (network-natural-bytes++ parcel 0 ssh-packet-size-index)
    
    (values (+ ssh-packet-payload-index payload-length) (+ packet-length 4))))

(define ssh-read-cipher-packet : (-> Input-Port Bytes Index Byte
                                     (Option (-> Bytes Bytes)) (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index) (->* (Bytes) (Natural Natural) Bytes)
                                     (Values Positive-Fixnum Positive-Fixnum))
  (lambda [/dev/tcpin parcel payload-capacity cipher-blocksize maybe-deflate decrypt! mac]
    (define head-block-end : Positive-Index (+ ssh-packet-size-index (max cipher-blocksize 8)))
    
    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-size-index head-block-end ssh-read-cipher-packet)
    (decrypt! parcel ssh-packet-size-index head-block-end)
    
    (define-values (packet-length _) (ssh-bytes->uint32 parcel ssh-packet-size-index))
    (define padding-length : Byte (bytes-ref parcel ssh-packet-padding-size-index))
    (define payload-length : Index (ssh-incoming-payload-size packet-length padding-length payload-capacity ssh-read-cipher-packet))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-read-bytes! /dev/tcpin parcel head-block-end packet-end ssh-read-cipher-packet)
    (decrypt! parcel head-block-end packet-end)

    (define checksum : Bytes (mac parcel 0 packet-end))
    (define mac-length : Index (bytes-length checksum))

    (when (> mac-length 0)
      (define digest (make-bytes mac-length))

      (ssh-read-bytes! /dev/tcpin digest 0 mac-length ssh-read-cipher-packet)

      (unless (bytes=? checksum digest)
        (ssh-raise-defence-error ssh-read-cipher-packet "inconsistent packet integrity"))

      (bytes-copy! parcel packet-end digest 0
                   (min mac-length (- (bytes-length parcel) packet-end))))
    
    (network-natural-bytes++ parcel 0 ssh-packet-size-index)
    
    (values (+ ssh-packet-payload-index payload-length) (+ packet-length mac-length 4))))

(define ssh-write-plain-packet : (-> Output-Port Bytes Natural Index)
  (lambda [/dev/tcpout parcel payload-length]
    (define-values (packet-length padding-length) (ssh-resolve-package-length payload-length 0))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-uint32->bytes packet-length parcel ssh-packet-size-index)
    (bytes-set! parcel ssh-packet-padding-size-index padding-length)

    (let ([sent (write-bytes parcel /dev/tcpout ssh-packet-size-index packet-end)])
      (flush-output /dev/tcpout)
      (network-natural-bytes++ parcel 0 ssh-packet-size-index)
      sent)))

(define ssh-write-cipher-packet : (-> Output-Port Bytes Natural (Option (->* (Bytes) (Natural Natural) Bytes))
                                      (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index) Byte (->* (Bytes) (Natural Natural) Bytes)
                                      Nonnegative-Fixnum)
  (lambda [/dev/tcpout parcel raw-payload-length maybe-inflate encrypt! cipher-blocksize mac]
    (define payload-length : Natural
      (cond [(not maybe-inflate) raw-payload-length]
            [else (let* ([payload (maybe-inflate parcel ssh-packet-payload-index (+ ssh-packet-payload-index payload-length))]
                         [payload-length (bytes-length payload)])
                    (bytes-copy! parcel ssh-packet-payload-index payload 0 payload-length)
                    payload-length)]))
    
    (define-values (packet-length padding-length) (ssh-resolve-package-length payload-length cipher-blocksize))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-uint32->bytes packet-length parcel ssh-packet-size-index)
    (bytes-set! parcel ssh-packet-padding-size-index padding-length)
    
    (let ([digest : Bytes (mac parcel 0 packet-end)])    ; generate checksum before encrypting
      (encrypt! parcel ssh-packet-size-index packet-end) ; skip the sequence number
      (let ([sent (+ (write-bytes parcel /dev/tcpout ssh-packet-size-index packet-end) (write-bytes digest /dev/tcpout))])
        (flush-output /dev/tcpout)
        (network-natural-bytes++ parcel 0 ssh-packet-size-index)
        sent))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-resolve-package-length : (-> Natural Byte (Values Index Integer))
  (lambda [payload-length cipher-blocksize]
    (let* ([idsize (max cipher-blocksize 8)]
           [packet-draft (+ 4 1 payload-length)]
           [padding-draft (- idsize (remainder packet-draft idsize))]
           [padding-draft (if (< padding-draft 4) (+ padding-draft idsize) padding-draft)]
           [thwarting-capacity (quotient (- #xFF padding-draft) idsize)]
           [random-length (+ padding-draft (* idsize (random (+ thwarting-capacity 1))))])
      (values (assert (- (+ packet-draft random-length) 4) index?)
              random-length))))

(define ssh-check-outgoing-payload-size : (-> Natural Index Boolean)
  (lambda [payload-length payload-capacity]
    (or (<= payload-length payload-capacity)
        (not (ssh-log-message 'debug "packet may overload based on local preference(~a > ~a), nonetheless, the peer may hold a much larger capacity"
                              (~size payload-length) (~size payload-capacity))))))

(define ssh-incoming-payload-size : (-> Index Byte Index Procedure Index)
  (lambda [packet-length padding-length payload-capacity fsrc]
    (define payload-length : Fixnum (- packet-length (+ padding-length 1)))
    
    (cond [(< payload-length 0)
           (ssh-raise-defence-error fsrc "invalid payload length: ~a" (~size payload-length))]
          [(> payload-length payload-capacity)
           (ssh-raise-defence-error fsrc "packet overlength: ~a > ~a" (~size payload-length) (~size payload-capacity))]
          [else payload-length])))

(define ssh-read-bytes! : (-> Input-Port Bytes Nonnegative-Fixnum Positive-Fixnum Procedure Void)
  (lambda [/dev/sshin parcel start end func]
    (when (eof-object? (read-bytes! parcel /dev/sshin start end))
      (ssh-raise-eof-error func "connection lost"))))
