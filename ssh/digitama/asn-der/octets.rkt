#lang typed/racket/base

;;; https://en.wikipedia.org/wiki/X.690
;;; https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-der-encoding-of-asn-1-types

(provide (all-defined-out) network-bytes->integer)

(require digimon/number)

(define-type (ASN-Octets->Datum t) (-> Bytes Natural Natural t))
(define-type ASN-Relative-Object-Identifier (Listof Index))
(define-type ASN-Object-Identifier (List* Byte Byte ASN-Relative-Object-Identifier))
(define-type ASN-Bitset (Pairof Bytes Byte))

(define asn-boolean->octets : (-> Any Bytes)
  (lambda [bool]
    (if bool (bytes #xFF) (bytes 0))))

(define asn-octets->boolean : (ASN-Octets->Datum Boolean)
  (lambda [bbool start end]
    (not (zero? (bytes-ref bbool start)))))

(define asn-integer->octets : (-> Integer Bytes)
  (lambda [mpint]
    (define os : Bytes (integer->network-bytes mpint))
    
    (cond [(or (<= mpint 0) (not (bitwise-bit-set? (bytes-ref os 0) 7))) os]
          [else (bytes-append (bytes #b00000000) os)])))

(define asn-null->octets : (-> Any Bytes)
  (lambda [nil]
    #""))

(define asn-object-identifier? : (-> Any Boolean : ASN-Object-Identifier)
  (lambda [datum]
    (and (asn-relative-object-identifier? datum)
         (pair? datum)
         (byte? (car datum))
         (pair? (cdr datum))
         (byte? (cadr datum)))))

(define asn-oid->octets : (-> ASN-Object-Identifier Bytes)
  (lambda [oid]
    (bytes-append (bytes (+ (* (car oid) 40) (cadr oid)))
                  (asn-relative-oid->octets (cddr oid)))))

(define asn-octets->oid : (ASN-Octets->Datum ASN-Object-Identifier)
  (lambda [boid start end]
    (define-values (q r) (quotient/remainder (bytes-ref boid start) 40))

    (list* q r (asn-octets->relative-oid boid (+ start 1) end))))

(define asn-relative-object-identifier? : (-> Any Boolean : ASN-Relative-Object-Identifier)
  (lambda [datum]
    (and (list? datum)
         (andmap index? datum))))

(define asn-relative-oid->octets : (-> ASN-Relative-Object-Identifier Bytes)
  (lambda [roid]
    (apply bytes
           (reverse
            (for/fold ([byte-tsil : (Listof Byte) null])
                      ([sub (in-list roid)])
              (cond [(< sub #b10000000) (cons sub byte-tsil)]
                    [else (append (asn-subid->octets sub) byte-tsil)]))))))

(define asn-octets->relative-oid : (ASN-Octets->Datum ASN-Relative-Object-Identifier)
  (lambda [boid start end]
    (define idxmax : Index (assert end index?))

    (let octets->subs : (Listof Index) ([sbus : (Listof Index) null]
                                        [idx : Natural start])
      (cond [(>= idx idxmax) (reverse sbus)]
            [else (let-values ([(sub span) (asn-octets->subid boid idx)])
                    (octets->subs (cons sub sbus) (+ idx span)))]))))

(define asn-bit-string? : (-> Any Boolean : ASN-Bitset)
  (lambda [datum]
    (and (pair? datum)
         (bytes? (car datum))
         (byte? (cdr datum)))))

(define asn-bit-string->octets : (-> ASN-Bitset Bytes)
  (lambda [bitstr]
    (define bits : Bytes (car bitstr))
    (define bidx : Fixnum (- (bytes-length bits) 1))

    ; TODO: removing trailing zeros
    (when (> bidx 0)
      (case (cdr bitstr)
        [(1) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11111110))]
        [(2) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11111100))]
        [(3) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11111000))]
        [(4) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11110000))]
        [(5) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11100000))]
        [(6) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b11000000))]
        [(7) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b10000000))]
        [(8) (bytes-set! bits bidx (bitwise-and (bytes-ref bits bidx) #b00000000))]))
    
    (bytes-append (bytes (cdr bitstr)) bits)))

(define asn-octets->bit-string : (ASN-Octets->Datum ASN-Bitset)
  (lambda [bbitstr start end]
    (cons (subbytes bbitstr (+ start 1) end)
          (bytes-ref bbitstr start))))

(define asn-octets->string/utf8 : (ASN-Octets->Datum String)
  (lambda [butf8 start end]
    (bytes->string/utf-8 butf8 #false start end)))

(define asn-octets->string/ia5 : (ASN-Octets->Datum String)
  (lambda [bia5 start end]
    (bytes->string/latin-1 bia5 #false start end)))

(define asn-octets->string/printable : (ASN-Octets->Datum String)
  (lambda [bprintable start end]
    (bytes->string/latin-1 bprintable #false start end)))

(define asn-string->octets/bmp : (-> String Bytes)
  (lambda [bmp]
    (define size : Index (string-length bmp))
    (define octets : Bytes (make-bytes (* size 2)))

    (let utf16->octets ([idx : Nonnegative-Fixnum 0])
      (when (< idx size)
        (integer->integer-bytes (char->integer (string-ref bmp idx)) 2 #false #true octets (+ idx idx))
        (utf16->octets (+ idx 1))))

    octets))

(define asn-octets->string/bmp : (ASN-Octets->Datum String)
  (lambda [bbmp start end]
    (define size : Index (assert (quotient (- end start) 2) index?))
    (define bmp : String (make-string size))

    (let octets->utf16 ([idx : Nonnegative-Fixnum 0])
      (when (< idx size)
        (define bidx : Natural (+ idx idx start))
        
        (string-set! bmp idx (integer->char (integer-bytes->integer bbmp #false #true bidx (+ bidx 2))))
        (octets->utf16 (+ idx 1))))
    
    bmp))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define asn-subid->octets : (-> Index (Listof Byte))
  (lambda [sub]
    (let subid->stetco ([byte-tsil : (Listof Byte) (list (remainder sub #b10000000))]
                        [sub : Nonnegative-Fixnum (quotient sub #b10000000)])
      (define r (remainder sub #b10000000))
      (cond [(> r 0) (subid->stetco (cons (bitwise-ior #b10000000 r) byte-tsil) (quotient sub #b10000000))]
            [else (reverse byte-tsil)]))))

(define asn-octets->subid : (-> Bytes Index (Values Index Index))
  (lambda [boid start]
    (let octets->subid ([idx : Natural start]
                        [oid : Natural 0])
      (define sub : Byte (bytes-ref boid idx))
      (define oid++ : Natural (bitwise-ior (arithmetic-shift oid 7) (bitwise-and sub #b01111111)))
      (cond [(< sub #b10000000) (values (assert oid++ index?) (assert (- idx start -1) index?))]
            [else (octets->subid (+ idx 1) oid++)]))))
