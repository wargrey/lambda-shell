#lang scribble/lp2

@(require digimon/tamer)

@(define-bib asn1-lib
   #:title    "ASN.1"
   #:author   (authors "Ryan Culpepper")
   #:date     2018
   #:url      "https://github.com/rmculpepper/asn1")

@(define-bib MS-DER
   #:title    "DER Encoding of ASN.1 Types"
   #:author   (org-author-name "Microsoft")
   #:date     2018
   #:url      "https://docs.microsoft.com/en-us/windows/desktop/SecCertEnroll/about-der-encoding-of-asn-1-types")

@handbook-story{ASN.1 Primitive Data Types}

This section demonstrates the implementation of @cite{X690}

@;tamer-smart-summary[]

@handbook-scenario{Lengths}

@tamer-repl[
 (asn-length 127)
 (asn-length 128)
 (asn-length 201)
 (asn-length 435)]

@handbook-scenario{Integers}

These testcases are defined in @~cite[asn1-lib].
@tamer-repl[
 (asn-primitive 0)
 (asn-primitive 1)
 (asn-primitive -1)
 (asn-primitive 127)
 (asn-primitive -127)
 (asn-primitive 128)
 (asn-primitive -128)
 (asn-primitive 255)
 (asn-primitive 256)
 (asn-primitive (expt 17 80))
 (asn-primitive (- (expt 23 81)))]

@handbook-scenario{Object Identifiers}

The first testcase is defined in @~cite[MS-DER].
@tamer-repl[
 (asn-primitive '(1 3 6 1 4 1 311 21 20) asn-oid)
 #;(asn-primitive '(2 999 3) asn-oid #|3, 0x883703|#)
 (asn-primitive '(8571 3 2) asn-relative-oid) #|4, 0xC27B0302|#]

@handbook-scenario{Bytes and Strings}

@tamer-repl[
 (asn-primitive (cons #"" 4))
 (asn-primitive (cons (symb0x-bytes '0x0A3B5F291CD0) 4))
 (asn-primitive "6.0.5361.2" asn-string/ia5)
 (asn-primitive "CertificateTemplate" asn-string/bmp)
 (asn-primitive "TestCN" asn-string/printable)
 (asn-primitive "λsh\nssh" asn-string/utf8)]

@handbook-scenario{Special Values}

@tamer-repl[
 (asn-primitive #true)
 (asn-primitive #false)
 (asn-primitive (void))]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <primitive>)]

@chunk[<primitive>
       (require "../../digitama/der/base.rkt")
       (require "../../digitama/der/primitive.rkt")

       (define symb0x-bytes
         (lambda [bs]
           (apply bytes (for/list ([octet (in-list (regexp-match* #px".." (substring (symbol->string bs) 2)))])
                          (string->number octet 16)))))
       
       (define asn-length
         (lambda [length]
           (define os (asn-length->octets length))
           (define-values (restored _) (asn-octets->length os))
           (cons restored (bytes->binstring os #:separator " "))))

       (define asn-primitive
         (lambda [datum [identifier #false]]
           (when (and (exact-integer? datum) (not (fixnum? datum)))
             (printf "Big Number: ~a~n" datum))

           (when (void? datum)
             (printf "NULL~n"))
           
           (define os (asn-primitive->bytes datum identifier))
           (define-values (restored _) (asn-bytes->primitive os))
           
           (if (equal? datum restored)
               (values (bytes->binstring os #:separator " ")
                       (bytes->hexstring os #:separator " "))
               (eprintf "~a~n" (bytes->hexstring os #:separator " ")))))]
