#lang typed/racket/base

;;; https://tools.ietf.org/html/rfc8017

(provide (all-defined-out))

(struct pkcs#1-hash
  ([der : Bytes]
   [method : (-> Bytes Bytes)])
  #:transparent
  #:type-name PKCS#1-Hash)

(define make-pkcs#1-hash : (-> (-> Bytes Bytes) #:DER (U Bytes (Listof Byte)) PKCS#1-Hash)
  (lambda [hash #:DER id]
    (pkcs#1-hash (if (list? id) (apply bytes id) id) hash)))

(define pkcs#1-id-sha1 : PKCS#1-Hash
  (make-pkcs#1-hash sha1-bytes
                    #:DER (list #x30 #x21 #| type SEQUENCE, length #x21 |#
                                #x30 #x09 #| type SEQUENCE, length #x09 |#
                                #x06 #x05 #| type OID, length #x05 |#
                                #x2b #x0e #x03 #x02 #x1a #| ID |#
                                #x05 #x00 #| NULL |#
                                #x04 #x14 #| type Octet String, followed by #x14-length degest |#)))

(define pkcs#1-id-sha256 : PKCS#1-Hash
  (make-pkcs#1-hash sha256-bytes
                    #:DER (list #x30 #x31 #| type SEQUENCE, length #x21 |#
                                #x30 #x0d #| type SEQUENCE, length #x0d |#
                                #x06 #x09 #| type OID, length #x09 |#
                                #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01 #| ID |#
                                #x05 #x00 #| NULL |#
                                #x04 #x20 #| type Octet String, followed by #x20-length degest |#)))
