#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc4253#section-6

(provide (all-defined-out))

(require digimon/number)
(require digimon/format)

(require "prompt.rkt")

(require "../diagnostics.rkt")
(require "../message/transport.rkt")
(require "../message/disconnection.rkt")

(require "../../datatype.rkt")

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
(define ssh-read-plain-packet : (-> Input-Port Bytes Index Byte (Option Log-Level) (Values Positive-Fixnum Positive-Fixnum))
  (lambda [/dev/tcpin parcel payload-capacity fault-tolerance debug-level]
    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-size-index ssh-packet-payload-index ssh-read-plain-packet)

    (define-values (packet-length _) (ssh-bytes->uint32 parcel ssh-packet-size-index))
    (define padding-length : Byte (bytes-ref parcel ssh-packet-padding-size-index))
    (define payload-length : Index (ssh-incoming-payload-size packet-length padding-length payload-capacity fault-tolerance ssh-read-plain-packet))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-payload-index packet-end ssh-read-plain-packet)
    (network-natural-bytes++ parcel 0 ssh-packet-size-index)
    (ssh-pretty-print-packet 'ssh-read-raw-packet parcel packet-end 8 debug-level #:cipher? #false)
    (values (+ ssh-packet-payload-index payload-length) (+ packet-length 4))))

(define ssh-read-cipher-packet : (-> Input-Port Bytes Index Byte Byte
                                     (Option (-> Bytes Bytes)) (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index) (->* (Bytes) (Natural Natural) Bytes)
                                     (Option Log-Level)
                                     (Values Positive-Fixnum Positive-Fixnum))
  (lambda [/dev/tcpin parcel payload-capacity fault-tolerance cipher-blocksize maybe-deflate decrypt! mac debug-level]
    (define blocksize : Byte (max cipher-blocksize 8))
    (define head-block-end : Index (+ ssh-packet-size-index blocksize))
    
    (ssh-read-bytes! /dev/tcpin parcel ssh-packet-size-index head-block-end ssh-read-cipher-packet)
    (ssh-pretty-print-packet 'ssh-read-cipher-packet parcel head-block-end blocksize debug-level)
    (decrypt! parcel ssh-packet-size-index head-block-end)
    
    (define-values (packet-length _) (ssh-bytes->uint32 parcel ssh-packet-size-index))
    (define padding-length : Byte (bytes-ref parcel ssh-packet-padding-size-index))
    (define payload-length : Index (ssh-incoming-payload-size packet-length padding-length payload-capacity fault-tolerance ssh-read-cipher-packet))
    (define packet-end : Positive-Fixnum (+ ssh-packet-padding-size-index packet-length))

    (ssh-read-bytes! /dev/tcpin parcel head-block-end packet-end ssh-read-cipher-packet)
    (ssh-pretty-print-packet 'ssh-read-cipher-packet parcel packet-end blocksize debug-level head-block-end)

    (when (> packet-end head-block-end)
      (decrypt! parcel head-block-end packet-end))
    
    (let* ([checksum (mac parcel 0 packet-end)]
           [mac-length : Index (bytes-length checksum)])
      (when (> mac-length 0)
        (define digest (make-bytes mac-length))

        (ssh-read-bytes! /dev/tcpin digest 0 mac-length ssh-read-cipher-packet)
        
        (unless (bytes=? checksum digest)
          (ssh-collapse (make-ssh:disconnect:mac:error #:source ssh-read-cipher-packet "corrupted packet") 'fatal)))
    
      (network-natural-bytes++ parcel 0 ssh-packet-size-index)
      (ssh-pretty-print-packet 'ssh-read-cipher-packet:plain parcel packet-end blocksize debug-level #:digest checksum #:cipher? #false #:2nd? #true)
      (values (+ ssh-packet-payload-index payload-length) (+ packet-length mac-length 4)))))

(define ssh-write-plain-packet : (-> Output-Port Bytes Natural (Option Log-Level) Index)
  (lambda [/dev/tcpout parcel payload-length debug-level]
    (define-values (packet-length padding-length) (ssh-resolve-package-length payload-length 0))
    (define packet-end : Positive-Integer (+ ssh-packet-padding-size-index packet-length))

    (ssh-uint32->bytes packet-length parcel ssh-packet-size-index)
    (bytes-set! parcel ssh-packet-padding-size-index padding-length)

    (ssh-pretty-print-packet 'ssh-write-raw-packet parcel packet-end 8 debug-level #:cipher? #false)
    
    (let ([sent (write-bytes parcel /dev/tcpout ssh-packet-size-index packet-end)])
      (flush-output /dev/tcpout)
      (network-natural-bytes++ parcel 0 ssh-packet-size-index)
      sent)))

(define ssh-write-cipher-packet : (-> Output-Port Bytes Natural (Option (->* (Bytes) (Natural Natural) Bytes))
                                      (->* (Bytes) (Natural Natural (Option Bytes) Natural Natural) Index) Byte (->* (Bytes) (Natural Natural) Bytes)
                                      (Option Log-Level)
                                      Nonnegative-Fixnum)
  (lambda [/dev/tcpout parcel raw-payload-length maybe-inflate encrypt! cipher-blocksize mac debug-level]
    (define payload-length : Natural
      (cond [(not maybe-inflate) raw-payload-length]
            [else (let* ([payload (maybe-inflate parcel ssh-packet-payload-index (+ ssh-packet-payload-index payload-length))]
                         [payload-length (bytes-length payload)])
                    (bytes-copy! parcel ssh-packet-payload-index payload 0 payload-length)
                    payload-length)]))
    
    (define-values (packet-length padding-length) (ssh-resolve-package-length payload-length cipher-blocksize))
    (define packet-end : Positive-Integer (+ ssh-packet-padding-size-index packet-length))

    (ssh-uint32->bytes packet-length parcel ssh-packet-size-index)
    (bytes-set! parcel ssh-packet-padding-size-index padding-length)
    
    (let ([digest (mac parcel 0 packet-end)]             ; generate checksum before encrypting
          [blocksize (max 8 cipher-blocksize)])
      (ssh-pretty-print-packet 'ssh-write-cipher-packet:plain parcel packet-end blocksize debug-level #:digest digest #:cipher? #false #:2nd? #true)

      (encrypt! parcel ssh-packet-size-index packet-end) ; encrypting skips the sequence number
      (ssh-pretty-print-packet 'ssh-write-cipher-packet parcel packet-end blocksize debug-level)
      
      (let ([sent (+ (write-bytes parcel /dev/tcpout ssh-packet-size-index packet-end) (write-bytes digest /dev/tcpout))])
        (flush-output /dev/tcpout)
        (network-natural-bytes++ parcel 0 ssh-packet-size-index)
        sent))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-resolve-package-length : (-> Natural Byte (Values Natural Integer))
  (lambda [payload-length cipher-blocksize]
    (let* ([idsize (max cipher-blocksize 8)]
           [packet-draft (+ 4 1 payload-length)]
           [padding-draft (- idsize (remainder packet-draft idsize))]
           [thwarting-capacity (quotient (- #xFF padding-draft) idsize)]
           [padding-length-4 (+ padding-draft (* idsize (random (+ thwarting-capacity 1))) -4)] ; TODO it seems that it pads too much
           [padding-length-4 (if (< padding-length-4 0) (abs (+ padding-length-4 idsize)) padding-length-4)])
      (values (+ packet-draft padding-length-4)
              (+ padding-length-4 4)))))

(define ssh-check-outgoing-payload-size : (-> Natural Index Byte Boolean)
  (lambda [payload-length payload-capacity fault-tolerance]
    (or (<= payload-length (+ payload-capacity fault-tolerance))
        (not (ssh-log-message 'warning "packet is overloaded based on local preference(~a > ~a + ~a), nonetheless, the peer may hold a much larger capacity"
                              (~size payload-length #:precision 3) (~size payload-capacity) fault-tolerance)))))

(define ssh-incoming-payload-size : (-> Index Byte Index Byte Procedure Index)
  (lambda [packet-length padding-length payload-capacity fault-tolerance fsrc]
    (define payload-length : Fixnum (- packet-length (+ padding-length 1)))
    
    (cond [(not (index? payload-length))
           (ssh-collapse (make-ssh:disconnect:protocol:error #:source fsrc "invalid payload length: ~a" (~size payload-length #:precision 3)) 'fatal)]
          [(> payload-length (+ payload-capacity fault-tolerance))
           (ssh-collapse (make-ssh:disconnect:protocol:error #:source fsrc "packet is too big: ~a > ~a"
                                                             (~size payload-length #:precision 3) (~size payload-capacity #:precision 3))
                         'fatal)]
          [else payload-length])))

(define ssh-pretty-print-packet : (->* (Symbol Bytes Natural Byte (Option Log-Level)) (Index #:digest Bytes #:cipher? Boolean #:2nd? Boolean) Void)
  (let ([/dev/pktout (open-output-bytes '/dev/pktout)])
    (lambda [source parcel packet-end blocksize level [start ssh-packet-size-index] #:digest [digest #""] #:cipher? [cipher? #true] #:2nd? [2nd? #false]]
      (unless (not level)
        (define padding-mark-idx-1 : Integer (if cipher? packet-end (- packet-end (+ (bytes-ref parcel ssh-packet-padding-size-index) 1))))

        (when (= start ssh-packet-size-index)
          (fprintf /dev/pktout "~a ~a (blocksize: ~a)~n"
                   (if 2nd? '>>> '==>) source (~size blocksize #:precision 3)))

        (with-asserts ([packet-end index?])
          (let pretty-print ([pidx : Nonnegative-Fixnum start])
            (when (< pidx packet-end)              
              (write-string (~r (- pidx ssh-packet-size-index) #:base 16 #:min-width 8 #:pad-string "0") /dev/pktout)
              (write-string ":  " /dev/pktout)

              (let pretty-print-line ([count : Index 0]
                                      [srahc : (Listof Char) null])
                (define idx : Nonnegative-Fixnum (+ pidx count))
                
                (cond [(>= idx packet-end)
                       ; NOTE: logger appends the #\newline
                       ; NOTE: the packet length should always be the multiple of blocksize
                       (write-string "| " /dev/pktout)
                       (for ([ch (in-list (reverse srahc))])
                         (write-char ch /dev/pktout))]
                      [(>= count blocksize)
                       (write-string "| " /dev/pktout)
                       (for ([ch (in-list (reverse srahc))])
                         (write-char ch /dev/pktout))
                       (newline /dev/pktout)
                       (pretty-print (+ pidx blocksize))]
                      [else (let ([octet (bytes-ref parcel idx)]
                                  [count++ (+ count 1)])
                              (define char : Char
                                (let ([c (integer->char octet)])
                                  (cond [(char-graphic? c) c]
                                        [(> idx padding-mark-idx-1) #\+]
                                        [else #\.])))

                              (when (< octet #x10) (write-char #\0 /dev/pktout))
                              (write-string (number->string octet 16) /dev/pktout)
                              (write-char (if (= idx padding-mark-idx-1) #\+ #\space) /dev/pktout)

                              (when (= (remainder count++ blocksize) 0)
                                (write-char #\space /dev/pktout))
                              
                              (pretty-print-line count++ (cons char srahc)))])))))

        (unless (bytes=? digest #"")
          (fprintf /dev/pktout "~n[digest: ~a]" (bytes->hex-string digest #:separator ":")))
          
        (ssh-log-message #:with-peer-name? #false level (bytes->string/utf-8 (get-output-bytes /dev/pktout #true)) #:data blocksize)))))

(define ssh-read-bytes! : (-> Input-Port Bytes Nonnegative-Fixnum Nonnegative-Fixnum Procedure Void)
  (lambda [/dev/sshin parcel start end func]
    (when (eof-object? (read-bytes! parcel /dev/sshin start end))
      (let ([eof-msg (make-ssh:disconnect:connection:lost #:source func "connection closed by peer")])
        (ssh-log-message 'info (ssh:msg:disconnect-description eof-msg) #:data eof-msg)
        (ssh-collapse eof-msg)))))
