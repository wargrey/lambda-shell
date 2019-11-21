#lang scribble/lp2

@(require digimon/tamer)

@(define-bib BF
   #:title  "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)"
   #:author (authors "B. Schneier")
   #:date   1994
   #:url    "https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html")

@handbook-story{The Blowfish Encryption Algorithm}

This section demonstrates the implementation of @~cite[BF].

@;tamer-smart-summary[]

@handbook-scenario[#:tag "bf-subkey"]{Key Expansion Examples}

@tamer-action[
 (blowfish-generate-subkeys key-test key-data)]

@handbook-scenario[#:tag "bf-cipher"]{Cipher Example}

@;tamer-action[
 (define state (make-aes-state-array))
 (aes-state-array-copy-from-bytes! state (symb0x->octets aes-plaintext))
 (aes-key-schedule-rotate! key-schedule128)
 (aes-add-round-key state key-schedule128 0)
 (aes-round-step state key-schedule128 1)
 (aes-round-step state key-schedule128 2)
 (aes-round-step state key-schedule128 3)
 (aes-round-step state key-schedule128 4)
 (aes-round-step state key-schedule128 5)
 (aes-round-step state key-schedule128 6)
 (aes-round-step state key-schedule128 7)
 (aes-round-step state key-schedule128 8)
 (aes-round-step state key-schedule128 9)
 (aes-round-done state key-schedule128 10)
 (aes-core-cipher! aes-plaintext aes-key128 aes-ciphertext)]

@handbook-scenario[#:tag "bf-vector"]{Example Vectors}

@;tamer-action[
 (aes-core-cipher '0x00112233445566778899aabbccddeeff '0x000102030405060708090a0b0c0d0e0f aes-ciphertext128)
 (aes-core-cipher '0x00112233445566778899aabbccddeeff '0x000102030405060708090a0b0c0d0e0f1011121314151617 aes-ciphertext192)
 (aes-core-cipher '0x00112233445566778899aabbccddeeff '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f aes-ciphertext256)]

@handbook-scenario[#:tag "bf-cbc"]{Real world example in CTR mode}

@;tamer-action[
 (define-values (c2s-plaintext c2s-ciphertext) (values '0x050000000C7373682D75736572617574 '0xb1b5681bd3596d80f34482a7a2f215ad))
 (define-values (c2s-iv c2s-key) (values '0x409265b173313e3a1c78c714b27bc72c '0x6df8cd5d2a6487aa257dc3e8119a20c1))
 
 (aes-ctr-cipher c2s-plaintext c2s-iv c2s-key c2s-ciphertext)]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer
         <blowfish>)]

@chunk[<blowfish>
       (require "inc/aes.rkt")
       (require "inc/misc.rkt")
       
       (require "../../digitama/algorithm/crypto/blowfish.rkt")
       (require "../../digitama/algorithm/crypto/blowfish/s-box.rkt")
       (require "../../digitama/algorithm/crypto/aes/s-box.rkt")
       (require "../../digitama/algorithm/crypto/aes/pretty.rkt")

       (define key-data (bytes #xFE #xDC #xBA #x98 #x76 #x54 #x32 #x10))
       (define key-test (bytes #xf0 #xe1 #xd2 #xc3 #xb4 #xa5 #x96 #x87
                               #x78 #x69 #x5a #x4b #x3c #x2d #x1e #x0f
                               #x00 #x11 #x22 #x33 #x44 #x55 #x66 #x77
                               #x88))

       (define key-outs
         (vector (bytes #xF9 #xAD #x59 #x7C #x49 #xDB #x00 #x5E)
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

       (define blowfish-generate-subkeys
         (lambda [keyfull keydata]
           (printf "data[~a]= ~a~n" (bytes-length keydata) (string-upcase (bytes->hex-string keydata)))

           (andmap values
                   (for/list ([size (in-range 1 (bytes-length keyfull))])
                     (define key (subbytes keyfull 0 size))
                     (define-values (parray sbox) (blowfish-make-boxes key))
                     (define out (blowfish-encrypt keydata parray sbox))
                     (define okay? (bytes=? out (vector-ref key-outs (sub1 size))))
                     (fprintf (if okay? (current-output-port) (current-error-port))
                              "c=~a k[~a]=~a~n"
                              (string-upcase (bytes->hex-string out)) (~r size #:min-width 2) (string-upcase (bytes->hex-string key)))
                     okay?))))

       (define aes-core-cipher!
         (lambda [0xplaintext 0xkey 0xciphertext]
           (define pool (symb0x->octets 0xplaintext))
           (define ciphertext (symb0x->octets 0xciphertext))
           (define key (symb0x->octets 0xkey))
           (define-values (encrypt! decrypt!) (aes-cipher! key))
           
           (encrypt! pool)
           
           (values (bytes->hex-string pool)
                   (bytes=? pool ciphertext))))
       
       (define aes-core-cipher
         (lambda [0xplaintext 0xkey 0xciphertext]
           (define plaintext (symb0x->octets 0xplaintext))
           (define ciphertext (symb0x->octets 0xciphertext))
           (define key (symb0x->octets 0xkey))
           (define-values (encrypt decrypt) (aes-cipher key))
           (define ctext (encrypt plaintext))
           (define ptext (decrypt ctext))
           (define encryption-okay? (bytes=? ctext ciphertext))
           (define decryption-okay? (bytes=? ptext plaintext))
           
           (printf "Plaintext     = ~a (~a Bytes)~n" (bytes->hex-string plaintext) (bytes-length plaintext))
           (printf "Cipher Key    = ~a (~a Bits)~n" (bytes->hex-string key) (* (bytes-length key) 8))
           (fprintf (if encryption-okay? (current-output-port) (current-error-port))
                    "Ciphertext    = ~a (~a Bytes)~n" (bytes->hex-string ctext) (bytes-length ctext))
           
           (when (not decryption-okay?)
             (eprintf "Deciphertext  = ~a (~a Bytes)~n" (bytes->hex-string ptext) (bytes-length ptext)))

           (and encryption-okay? decryption-okay?)))
       
       (define aes-ctr-cipher
         (lambda [0xplaintext 0xIV 0xkey 0xciphertext]
           (define plaintext (symb0x->octets 0xplaintext))
           (define ciphertext (symb0x->octets 0xciphertext))
           (define IV (symb0x->octets 0xIV))
           (define key (symb0x->octets 0xkey))
           (define-values (encrypt decrypt) (aes-cipher-ctr IV key))
           (define ctext (encrypt plaintext))
           (define ptext (decrypt ctext))
           (define encryption-okay? (bytes=? ctext ciphertext))
           (define decryption-okay? (bytes=? ptext plaintext))
           
           (printf "Plaintext     = ~a (~a Bytes)~n" (bytes->hex-string plaintext) (bytes-length plaintext))
           (printf "InitialVector = ~a (~a Bits)~n" (bytes->hex-string IV) (* (bytes-length IV) 8))
           (printf "Cipher Key    = ~a (~a Bits)~n" (bytes->hex-string key) (* (bytes-length key) 8))
           (fprintf (if encryption-okay? (current-output-port) (current-error-port))
                    "Ciphertext    = ~a (~a Bytes)~n" (bytes->hex-string ctext) (bytes-length ctext))
           
           (when (not decryption-okay?)
             (eprintf "Deciphertext  = ~a (~a Bytes)~n" (bytes->hex-string ptext) (bytes-length ptext)))

           (and encryption-okay? decryption-okay?)))]
