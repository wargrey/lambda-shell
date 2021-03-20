#lang scribble/lp2

@(require digimon/tamer)

@(define-bib BF
   #:title  "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)"
   #:author (authors "Bruce Schneier")
   #:date   1994
   #:url    "https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html")

@(define-bib TBEA
   #:title  "The Blowfish Encryption Algorithm"
   #:author (authors "Bruce Schneier")
   #:date   2005
   #:url    "https://www.schneier.com/academic/blowfish/")

@(define-bib S63DPS
   #:title  "S63 Data Protection Scheme"
   #:author (org-author-name "INTERNATIONAL HYDROGRAPHIC ORGANISATION")
   #:date   2012)

@handbook-story{The Blowfish Encryption Algorithm}

This section demonstrates the implementation of @~cite[BF] and @~cite[TBEA].

@;tamer-smart-summary[]

@handbook-scenario[#:tag "bf-subkey"]{Generate Subkeys}

@tamer-action[
 (bf-generate-subkeys key-test key-data)]

@handbook-scenario[#:tag "bf-vector"]{Test Vectors}

@tamer-action[
 (bf-cipher-ecb ecb-data plain-data cipher-data)]

@handbook-scenario[#:tag "bf-cbc"]{Chain mode Test}

@tamer-action[
 (bf-cipher-cbc cbc-data cbc-iv cbc-key cbc-ok)]

@handbook-scenario[#:tag "bf-enc"]{ENC Cell Permit Examples}

Blowfish algorithm is used to encrypt the ENC, so let's try some test vectors that provided in @~cite[S63DPS].

@tamer-action[
 (define HW-ID (string->bytes/utf-8 (string #\1 #\2 #\3 #\4 #\8)))
 (define HW-ID6 (bytes-append HW-ID (bytes (bytes-ref HW-ID 0))))
 (define cell-key1 (bytes #xC1 #xCB #x51 #x8E #x9C))
 (define cell-key2 (bytes #x42 #x15 #x71 #xCC #x66))
 (define-values (encrypt decrypt) (blowfish-cipher HW-ID6))
 (define eck1 (encrypt (bytes-append cell-key1 (bytes 03 03 03))))
 (define eck2 (encrypt (bytes-append cell-key2 (bytes 03 03 03))))
 (string-upcase (bytes->hex-string eck1))
 (string-upcase (bytes->hex-string eck2))]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <blowfish>)]

@chunk[<blowfish>
       (require "inc/misc.rkt")
       
       (require "../../digitama/algorithm/crypto/blowfish.rkt")
       (require "../../digitama/algorithm/crypto/blowfish/s-box.rkt")
       
       (require "../../digitama/algorithm/crypto/utility.rkt")

       (define key-data (bytes #xFE #xDC #xBA #x98 #x76 #x54 #x32 #x10))
       (define key-test (bytes #xf0 #xe1 #xd2 #xc3 #xb4 #xa5 #x96 #x87
                               #x78 #x69 #x5a #x4b #x3c #x2d #x1e #x0f
                               #x00 #x11 #x22 #x33 #x44 #x55 #x66 #x77
                               #x88))

       (define key-outs (vector (bytes #xF9 #xAD #x59 #x7C #x49 #xDB #x00 #x5E)
                                (bytes #xE9 #x1D #x21 #xC1 #xD9 #x61 #xA6 #xD6)
                                (bytes #xE9 #xC2 #xB7 #x0A #x1B #xC6 #x5C #xF3)
                                (bytes #xBE #x1E #x63 #x94 #x08 #x64 #x0F #x05)
                                (bytes #xB3 #x9E #x44 #x48 #x1B #xDB #x1E #x6E)
                                (bytes #x94 #x57 #xAA #x83 #xB1 #x92 #x8C #x0D)
                                (bytes #x8B #xB7 #x70 #x32 #xF9 #x60 #x62 #x9D)
                                (bytes #xE8 #x7A #x24 #x4E #x2C #xC8 #x5E #x82)
                                (bytes #x15 #x75 #x0E #x7A #x4F #x4E #xC5 #x77)
                                (bytes #x12 #x2B #xA7 #x0B #x3A #xB6 #x4A #xE0)
                                (bytes #x3A #x83 #x3C #x9A #xFF #xC5 #x37 #xF6)
                                (bytes #x94 #x09 #xDA #x87 #xA9 #x0F #x6B #xF2)
                                (bytes #x88 #x4F #x80 #x62 #x50 #x60 #xB8 #xB4)
                                (bytes #x1F #x85 #x03 #x1C #x19 #xE1 #x19 #x68)
                                (bytes #x79 #xD9 #x37 #x3A #x71 #x4C #xA3 #x4F)
                                (bytes #x93 #x14 #x28 #x87 #xEE #x3B #xE1 #x5C)
                                (bytes #x03 #x42 #x9E #x83 #x8C #xE2 #xD1 #x4B)
                                (bytes #xA4 #x29 #x9E #x27 #x46 #x9F #xF6 #x7B)
                                (bytes #xAF #xD5 #xAE #xD1 #xC1 #xBC #x96 #xA8)
                                (bytes #x10 #x85 #x1C #x0E #x38 #x58 #xDA #x9F)
                                (bytes #xE6 #xF5 #x1E #xD7 #x9B #x9D #xB2 #x1F)
                                (bytes #x64 #xA6 #xE1 #x4A #xFD #x36 #xB4 #x6F)
                                (bytes #x80 #xC7 #xD7 #xD4 #x5A #x54 #x79 #xAD)
                                (bytes #x05 #x04 #x4B #x62 #xFA #x52 #xD0 #x80)))
       
       (define ecb-data (vector (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                (bytes #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)
                                (bytes #x30 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                (bytes #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11)
                                (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                (bytes #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11)
                                (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                (bytes #xFE #xDC #xBA #x98 #x76 #x54 #x32 #x10)
                                (bytes #x7C #xA1 #x10 #x45 #x4A #x1A #x6E #x57)
                                (bytes #x01 #x31 #xD9 #x61 #x9D #xC1 #x37 #x6E)
                                (bytes #x07 #xA1 #x13 #x3E #x4A #x0B #x26 #x86)
                                (bytes #x38 #x49 #x67 #x4C #x26 #x02 #x31 #x9E)
                                (bytes #x04 #xB9 #x15 #xBA #x43 #xFE #xB5 #xB6)
                                (bytes #x01 #x13 #xB9 #x70 #xFD #x34 #xF2 #xCE)
                                (bytes #x01 #x70 #xF1 #x75 #x46 #x8F #xB5 #xE6)
                                (bytes #x43 #x29 #x7F #xAD #x38 #xE3 #x73 #xFE)
                                (bytes #x07 #xA7 #x13 #x70 #x45 #xDA #x2A #x16)
                                (bytes #x04 #x68 #x91 #x04 #xC2 #xFD #x3B #x2F)
                                (bytes #x37 #xD0 #x6B #xB5 #x16 #xCB #x75 #x46)
                                (bytes #x1F #x08 #x26 #x0D #x1A #xC2 #x46 #x5E)
                                (bytes #x58 #x40 #x23 #x64 #x1A #xBA #x61 #x76)
                                (bytes #x02 #x58 #x16 #x16 #x46 #x29 #xB0 #x07)
                                (bytes #x49 #x79 #x3E #xBC #x79 #xB3 #x25 #x8F)
                                (bytes #x4F #xB0 #x5E #x15 #x15 #xAB #x73 #xA7)
                                (bytes #x49 #xE9 #x5D #x6D #x4C #xA2 #x29 #xBF)
                                (bytes #x01 #x83 #x10 #xDC #x40 #x9B #x26 #xD6)
                                (bytes #x1C #x58 #x7F #x1C #x13 #x92 #x4F #xEF)
                                (bytes #x01 #x01 #x01 #x01 #x01 #x01 #x01 #x01)
                                (bytes #x1F #x1F #x1F #x1F #x0E #x0E #x0E #x0E)
                                (bytes #xE0 #xFE #xE0 #xFE #xF1 #xFE #xF1 #xFE)
                                (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                (bytes #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)
                                (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                (bytes #xFE #xDC #xBA #x98 #x76 #x54 #x32 #x10)))

       (define plain-data (vector (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                  (bytes #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)
                                  (bytes #x10 #x00 #x00 #x00 #x00 #x00 #x00 #x01)
                                  (bytes #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11)
                                  (bytes #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11)
                                  (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                  (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                  (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                  (bytes #x01 #xA1 #xD6 #xD0 #x39 #x77 #x67 #x42)
                                  (bytes #x5C #xD5 #x4C #xA8 #x3D #xEF #x57 #xDA)
                                  (bytes #x02 #x48 #xD4 #x38 #x06 #xF6 #x71 #x72)
                                  (bytes #x51 #x45 #x4B #x58 #x2D #xDF #x44 #x0A)
                                  (bytes #x42 #xFD #x44 #x30 #x59 #x57 #x7F #xA2)
                                  (bytes #x05 #x9B #x5E #x08 #x51 #xCF #x14 #x3A)
                                  (bytes #x07 #x56 #xD8 #xE0 #x77 #x47 #x61 #xD2)
                                  (bytes #x76 #x25 #x14 #xB8 #x29 #xBF #x48 #x6A)
                                  (bytes #x3B #xDD #x11 #x90 #x49 #x37 #x28 #x02)
                                  (bytes #x26 #x95 #x5F #x68 #x35 #xAF #x60 #x9A)
                                  (bytes #x16 #x4D #x5E #x40 #x4F #x27 #x52 #x32)
                                  (bytes #x6B #x05 #x6E #x18 #x75 #x9F #x5C #xCA)
                                  (bytes #x00 #x4B #xD6 #xEF #x09 #x17 #x60 #x62)
                                  (bytes #x48 #x0D #x39 #x00 #x6E #xE7 #x62 #xF2)
                                  (bytes #x43 #x75 #x40 #xC8 #x69 #x8F #x3C #xFA)
                                  (bytes #x07 #x2D #x43 #xA0 #x77 #x07 #x52 #x92)
                                  (bytes #x02 #xFE #x55 #x77 #x81 #x17 #xF1 #x2A)
                                  (bytes #x1D #x9D #x5C #x50 #x18 #xF7 #x28 #xC2)
                                  (bytes #x30 #x55 #x32 #x28 #x6D #x6F #x29 #x5A)
                                  (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                  (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                  (bytes #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)
                                  (bytes #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)
                                  (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                  (bytes #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
                                  (bytes #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)))

       (define cipher-data (vector (bytes #x4E #xF9 #x97 #x45 #x61 #x98 #xDD #x78)
                                   (bytes #x51 #x86 #x6F #xD5 #xB8 #x5E #xCB #x8A)
                                   (bytes #x7D #x85 #x6F #x9A #x61 #x30 #x63 #xF2)
                                   (bytes #x24 #x66 #xDD #x87 #x8B #x96 #x3C #x9D)
                                   (bytes #x61 #xF9 #xC3 #x80 #x22 #x81 #xB0 #x96)
                                   (bytes #x7D #x0C #xC6 #x30 #xAF #xDA #x1E #xC7)
                                   (bytes #x4E #xF9 #x97 #x45 #x61 #x98 #xDD #x78)
                                   (bytes #x0A #xCE #xAB #x0F #xC6 #xA0 #xA2 #x8D)
                                   (bytes #x59 #xC6 #x82 #x45 #xEB #x05 #x28 #x2B)
                                   (bytes #xB1 #xB8 #xCC #x0B #x25 #x0F #x09 #xA0)
                                   (bytes #x17 #x30 #xE5 #x77 #x8B #xEA #x1D #xA4)
                                   (bytes #xA2 #x5E #x78 #x56 #xCF #x26 #x51 #xEB)
                                   (bytes #x35 #x38 #x82 #xB1 #x09 #xCE #x8F #x1A)
                                   (bytes #x48 #xF4 #xD0 #x88 #x4C #x37 #x99 #x18)
                                   (bytes #x43 #x21 #x93 #xB7 #x89 #x51 #xFC #x98)
                                   (bytes #x13 #xF0 #x41 #x54 #xD6 #x9D #x1A #xE5)
                                   (bytes #x2E #xED #xDA #x93 #xFF #xD3 #x9C #x79)
                                   (bytes #xD8 #x87 #xE0 #x39 #x3C #x2D #xA6 #xE3)
                                   (bytes #x5F #x99 #xD0 #x4F #x5B #x16 #x39 #x69)
                                   (bytes #x4A #x05 #x7A #x3B #x24 #xD3 #x97 #x7B)
                                   (bytes #x45 #x20 #x31 #xC1 #xE4 #xFA #xDA #x8E)
                                   (bytes #x75 #x55 #xAE #x39 #xF5 #x9B #x87 #xBD)
                                   (bytes #x53 #xC5 #x5F #x9C #xB4 #x9F #xC0 #x19)
                                   (bytes #x7A #x8E #x7B #xFA #x93 #x7E #x89 #xA3)
                                   (bytes #xCF #x9C #x5D #x7A #x49 #x86 #xAD #xB5)
                                   (bytes #xD1 #xAB #xB2 #x90 #x65 #x8B #xC7 #x78)
                                   (bytes #x55 #xCB #x37 #x74 #xD1 #x3E #xF2 #x01)
                                   (bytes #xFA #x34 #xEC #x48 #x47 #xB2 #x68 #xB2)
                                   (bytes #xA7 #x90 #x79 #x51 #x08 #xEA #x3C #xAE)
                                   (bytes #xC3 #x9E #x07 #x2D #x9F #xAC #x63 #x1D)
                                   (bytes #x01 #x49 #x33 #xE0 #xCD #xAF #xF6 #xE4)
                                   (bytes #xF2 #x1E #x9A #x77 #xB7 #x1C #x49 #xBC)
                                   (bytes #x24 #x59 #x46 #x88 #x57 #x54 #x36 #x9A)
                                   (bytes #x6B #x5C #x5A #x9C #x5D #x9E #x0A #x5A)))

       
       (define cbc-data (bytes-append #"7654321 Now is the time for " (bytes 0)))
       (define cbc-iv (bytes #xfe #xdc #xba #x98 #x76 #x54 #x32 #x10))
       (define cbc-key (bytes #x01 #x23 #x45 #x67 #x89 #xab #xcd #xef
                              #xf0 #xe1 #xd2 #xc3 #xb4 #xa5 #x96 #x87))
       (define cbc-ok (bytes #x6B #x77 #xB4 #xD6 #x30 #x06 #xDE #xE6
                             #x05 #xB1 #x56 #xE2 #x74 #x03 #x97 #x93
                             #x58 #xDE #xB9 #xE7 #x15 #x46 #x16 #xD9
                             #x59 #xF1 #x65 #x2B #xD5 #xFF #x92 #xCC))
       
       (define bf-generate-subkeys
         (lambda [keyfull keydata]
           (printf "data[~a]= ~a~n" (bytes-length keydata) (string-upcase (bytes->hexstring keydata)))

           (andmap values
                   (for/list ([size (in-range 1 (bytes-length keyfull))])
                     (define key (subbytes keyfull 0 size))
                     (define-values (parray sbox) (blowfish-make-boxes key))
                     (define out (blowfish-encrypt keydata parray sbox))
                     (define okay? (bytes=? out (vector-ref key-outs (sub1 size))))

                     (fprintf (if okay? (current-output-port) (current-error-port))
                              "c=~a k[~a]=~a~n"
                              (string-upcase (bytes->hexstring out)) (~r size #:min-width 2) (string-upcase (bytes->hexstring key)))

                     okay?))))

       (define bf-cipher-ecb
         (lambda [keys plaintexts ciphertexts]
           (printf "key bytes\t\tclear bytes\t\tcipher bytes~n")

           (andmap values
                   (for/list ([key (in-vector keys)]
                              [plaintext (in-vector plaintexts)]
                              [ciphertext (in-vector ciphertexts)])
                     (define-values (encrypt decrypt) (blowfish-cipher key))
                     (define cout (encrypt plaintext))
                     (define pout (decrypt ciphertext))
                     (define okay? (and (bytes=? cout ciphertext) (bytes=? pout plaintext)))

                     (fprintf (if okay? (current-output-port) (current-error-port))
                              "~a\t~a\t~a~n"
                              (string-upcase (bytes->hexstring key)) (string-upcase (bytes->hexstring pout)) (string-upcase (bytes->hexstring cout)))

                     okay?))))
       
       (define bf-cipher-cbc
         (lambda [data IV key ciphertext]
           (define cipher-size (bytes-length ciphertext))
           (define plaintext (plaintext-0pad data blowfish-blocksize))
           (define-values (encrypt decrypt) (blowfish-cipher-cbc IV key))
           (define cout (encrypt plaintext))
           (define pout (decrypt cout))
           (define cokay? (bytes=? (subbytes cout 0 cipher-size) ciphertext))
           (define pokay? (bytes=? pout plaintext))
           
           (printf "chain mode test data~n")
           (printf "key[~a]\t  =~a~n" (bytes-length key) (string-upcase (bytes->hexstring key)))
           (printf "iv[~a]\t  =~a~n" (bytes-length IV) (string-upcase (bytes->hexstring IV)))
           (printf "data[~a]  =\"~a\" (including trailing '\\0')~n" (bytes-length data) data)

           (fprintf (if pokay? (current-output-port) (current-error-port))
                    "data[~a]  =~a~n" (bytes-length data) (string-upcase (bytes->hexstring data)))
           
           (fprintf (if cokay? (current-output-port) (current-error-port))
                    "cbc cipher text~ncipher[~a]=~a~n" cipher-size (string-upcase (bytes->hexstring ciphertext)))

           (and cokay? pokay?)))]
