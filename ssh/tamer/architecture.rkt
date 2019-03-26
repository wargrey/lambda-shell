#lang scribble/lp2

@(require digimon/tamer)

@(define-bib SSH-ARCH
   #:title    "The Secure Shell Protocol Architecture"
   #:author   (org-author-name "RFC4251")
   #:date     2006
   #:url      "https://tools.ietf.org/html/rfc4251")

@(define-bib HMAC-SHA
   #:title    " Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512"
   #:author   (org-author-name "RFC4231")
   #:date     2005
   #:url      "https://tools.ietf.org/html/rfc4231")

@handbook-story{The Secure Shell Protocol Architecture}

This section demonstrates the implementation of @~cite[SSH-ARCH].

@;tamer-smart-summary[]

@handbook-scenario{Data Type Representation}

@tamer-action[
 (mpint '0x0)
 (mpint '0x9a378f9b2e332a7)
 (mpint '0x80)
 (mpint '0x-1234)
 (mpint '0x-deadbeef)]

@tamer-action[
 (namelist '())
 (namelist '(zlib))
 (namelist '(zlib none))]

@handbook-scenario{Data Integrity Algorithms}

These test cases are defined in @~cite[HMAC-SHA].

@tamer-action[
 (hmac-sha256 (make-bytes 20 #x0B) #"Hi There")
 (hmac-sha256 #"Jefe" #"what do ya want for nothing?")
 (hmac-sha256 (make-bytes 20 #xAA) (make-bytes 50 #xDD))
 (hmac-sha256 (apply bytes (range #x01 #x1A)) (make-bytes 50 #xCD))
 (hmac-sha256-128 (make-bytes 20 #x0C) #"Test With Truncation")
 (hmac-sha256 (make-bytes 131 #xAA) #"Test Using Larger Than Block-Size Key - Hash Key First")
 (hmac-sha256 (make-bytes 131 #xAA) #"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<architecture:*>|)]

@chunk[|<architecture:*>|
       (module+ story
         <datatype>)]

@chunk[<datatype>
       (require "../digitama/datatype.rkt")
       (require "../digitama/algorithm/hmac.rkt")

       (define mpint->symbol
         (lambda [mphex]
           (string->symbol (string-append "0x" (number->string mphex 16)))))

       (define bytes->hex-string
         (lambda [bs [sep " "]]
           (string-join (for/list ([b (in-bytes bs)])
                          (cond [(>= b #x10) (number->string b 16)]
                                [else (format "0~a" (number->string b 16))]))
                        sep)))
       
       (define mpint
         (lambda [hex]
           (define raw (~a hex))
           (define mphex (string->number (substring raw 2) 16))
           (define bs (ssh-mpint->bytes mphex))
           (define-values (restored _) (ssh-bytes->mpint bs))
           (cons (mpint->symbol restored) (bytes->hex-string bs))))

       (define namelist
         (lambda [names]
           (define bs (ssh-namelist->bytes names))
           (define-values (restored _) (ssh-bytes->namelist bs))
           (cons restored (bytes->hex-string bs))))

       (define hmac-sha256
         (lambda [key message]
           (printf "Key  = ~a (~a Bytes)~n" (bytes->hex-string key "") (bytes-length key))
           (printf "Data = ~a (~a Bytes)~n" (bytes->hex-string message "") (bytes-length message))
           (bytes->hex-string (ssh-hmac-sha256 key message) "")))

       (define hmac-sha256-128
         (lambda [key message]
           (printf "Key  = ~a (~a Bytes)~n" (bytes->hex-string key "") (bytes-length key))
           (printf "Data = ~a (~a Bytes)~n" (bytes->hex-string message "") (bytes-length message))
           (bytes->hex-string (ssh-hmac-sha256-128 key message) "")))]
