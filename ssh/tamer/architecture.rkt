#lang scribble/lp2

@(require digimon/tamer)

@(define-bib SSH-ARCH
   #:title    "The Secure Shell Protocol Architecture"
   #:author   (org-author-name "RFC4251")
   #:date     2006
   #:url      "https://tools.ietf.org/html/rfc4251")

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

       (define mpint->symbol
         (lambda [mphex]
           (string->symbol (string-append "0x" (number->string mphex 16)))))

       (define bytes->hex-string
         (lambda [bs]
           (string-join (for/list ([b (in-bytes bs)])
                          (cond [(>= b #x10) (number->string b 16)]
                                [else (format "0~a" b)]))
                        " ")))
       
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
           (cons restored (bytes->hex-string bs))))]
