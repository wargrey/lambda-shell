#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

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
(define ssh-read-plain-packet : (-> Input-Port Index (Values Bytes Byte Nonnegative-Fixnum))
  (lambda [/dev/tcpin payload-capacity]
    (define length-fields : Bytes (ssh-read-bytes /dev/tcpin 5 ssh-read-plain-packet))
    (define-values (packet-length _) (ssh-bytes->uint32 length-fields))
    (define padding-length : Byte (bytes-ref length-fields 4))
    (define payload-length : Index (check-incoming-payload-size packet-length padding-length payload-capacity))
    (define payload : Bytes (ssh-read-bytes /dev/tcpin payload-length ssh-read-plain-packet))
    (define pads : Bytes (ssh-read-bytes /dev/tcpin padding-length ssh-read-plain-packet))

    (values payload 0 (+ packet-length 4))))

(define ssh-read-cipher-packet : (-> Input-Port Bytes Index Byte
                                     (Option (-> Bytes Bytes)) (->* (Bytes) (Index Index (Option Bytes) Index Index) Index) (-> Bytes Bytes)
                                     (Values Bytes Byte Nonnegative-Fixnum))
  (lambda [/dev/tcpin plaintext payload-capacity cipher-blocksize maybe-deflate decrypt! mac]
    (define head-block : Bytes (ssh-read-bytes /dev/tcpin (max cipher-blocksize 8) ssh-read-cipher-packet))
    (define headsize : Index (decrypt! head-block))
    (define-values (packet-length _) (ssh-bytes->uint32 head-block))
    (define padding-length : Byte (bytes-ref plaintext 4))
    (define payload-length : Index (check-incoming-payload-size packet-length padding-length payload-capacity))
    (define ciphertext : Bytes (ssh-read-bytes /dev/tcpin (- packet-length (- headsize 4)) ssh-read-cipher-packet))
    
    #;(cond [(not maybe-mac) (ssh-read-bytes /dev/tcpin mac-length)]
            [else #""])
    
    (values plaintext 5 (+ packet-length #;mac-length 4))))

(define ssh-write-plain-packet : (-> Output-Port Bytes Index Index)
  (lambda [/dev/tcpout payload payload-capacity]
    (define payload-length : Index (check-outgoing-payload-size payload payload-capacity))
    (define-values (packet-length padding-length) (resolve-package-length payload-length 0))
    (define packet : Bytes (bytes-append (ssh-uint32->bytes packet-length) (bytes padding-length) payload (ssh-cookie padding-length)))
    (define sent : Index (write-bytes packet /dev/tcpout))
    
    (flush-output /dev/tcpout)

    sent))

(define ssh-write-cipher-packet : (-> Output-Port Bytes Index Byte
                                      (Option (-> Bytes Bytes)) (->* (Bytes) (Index Index (Option Bytes) Index Index) Index) (-> Bytes Bytes)
                                      Nonnegative-Fixnum)
  (lambda [/dev/tcpout payload-raw payload-capacity cipher-blocksize maybe-inflate encrypt! mac]
    (define-values (payload payload-length)
      (let ([rawload-length (check-outgoing-payload-size payload-raw payload-capacity)])
        (cond [(not maybe-inflate) (values payload-raw rawload-length)]
              [else (let ([payload (maybe-inflate payload-raw)])
                      (values payload (bytes-length payload)))])))

    (define sequence-number : Index 0)
    (define-values (packet-length padding-length) (resolve-package-length payload-length cipher-blocksize))
    (define sequence+raw-packet : Bytes
      (bytes-append (ssh-uint32->bytes sequence-number)
                    (ssh-uint32->bytes packet-length) (bytes padding-length) payload (ssh-cookie padding-length)))
    
    (define digest : Bytes (mac sequence+raw-packet))        ; generate the checksum before encrypting
    (define ciphertext-end (encrypt! sequence+raw-packet 4)) ; skip the sequence number
    
    (define sent : Nonnegative-Fixnum
      (+ (write-bytes sequence+raw-packet /dev/tcpout 4 ciphertext-end)
         (write-bytes digest /dev/tcpout)))
    
    (flush-output /dev/tcpout)

    sent))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define resolve-package-length : (-> Index Byte (Values Index Byte))
  (lambda [payload-length cipher-blocksize]
    (let* ([idsize (max cipher-blocksize 8)]
           [packet-draft (+ 4 1 payload-length)]
           [padding-draft (- idsize (remainder packet-draft idsize))]
           [padding-draft (if (< padding-draft 4) (+ padding-draft idsize) padding-draft)]
           [thwarting-capacity (quotient (- #xFF padding-draft) idsize)]
           [random-length (+ padding-draft (* idsize (random (+ thwarting-capacity 1))))])
      (values (assert (- (+ packet-draft random-length) 4) index?)
              (assert random-length byte?)))))

(define check-outgoing-payload-size : (-> Bytes Index Index)
  (lambda [payload payload-capacity]
    ;; NOTE: we do not forbid the overloaded packet since we do not know the payload capacity that the peer holds.
    (define size : Index (bytes-length payload))
    
    (when (> size payload-capacity)
      (ssh-log-message 'debug "packet may overload based on local preference(~a > ~a), nonetheless, the peer may hold a much larger capacity"
                       (~size size) (~size payload-capacity)))

    size))

(define check-incoming-payload-size : (-> Index Byte Index Index)
  (lambda [packet-length padding-length payload-capacity]
    (define payload-length : Fixnum (- packet-length (+ padding-length 1)))
    
    (cond [(< payload-length 0)
           (ssh-raise-defence-error ssh-read-plain-packet "invalid payload length: ~a" (~size payload-length))]
          [(> payload-length payload-capacity)
           (ssh-raise-defence-error ssh-read-plain-packet "packet overlength: ~a > ~a" (~size payload-length) (~size payload-capacity))]
          [else payload-length])))

(define ssh-read-bytes : (-> Input-Port Integer Procedure Bytes)
  (lambda [/dev/sshin amt func]
    (define bs : (U Bytes EOF) (read-bytes amt /dev/sshin))
    (cond [(eof-object? bs) (ssh-raise-eof-error func "connection lost")]
          [else bs])))
