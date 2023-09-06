#lang scribble/lp2

@(require digimon/tamer)

@(define-bib AES
   #:title  "Advanced Encryption Standard (AES) (FIPS PUB 197)"
   #:author (org-author-name "National Institute of Standards and Technology")
   #:date   2001
   #:url    "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf")

@(define-bib libssh2
   #:title  "A client-side C library implementing the SSH2 protocol"
   #:author (org-author-name "The libssh2 Project")
   #:date   2018
   #:url    "https://www.libssh2.org")

@handbook-story{Advanced Encryption Standard (AES)}

This section demonstrates the implementation of @~cite[AES].

@tamer-smart-summary[]

@handbook-scenario[#:tag "aes-key-expansion"]{Key Expansion Examples}

@tamer-repl[
 (define key-schedule128 (aes-key-schedule aes-key128 4 '0xb6630ca6))
 (define key-schedule192 (aes-key-schedule aes-key192 6 '0x01002202))
 (define key-schedule256 (aes-key-schedule aes-key256 8 '0x706c631e))]

@handbook-scenario[#:tag "aes-cipher"]{Cipher Example}

@tamer-repl[
 (define state (make-aes-state-array))
 (aes-state-array-copy-from-bytes! state (assert (symb0x->octets aes-plaintext)))
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
 (aes-round-done state key-schedule128 10)]

@tamer-note{aes-core-cipher!}

@handbook-chunk[<aes-core-spec!>
  (context "aes-core-cipher!" #:do
    (it-check-aes/core! aes-plaintext aes-key128 aes-ciphertext))]

@handbook-scenario[#:tag "aes-vectors"]{Example Vectors}

@tamer-note{aes-core-cipher}
@handbook-chunk[<aes-core-spec>
  (context "aes-core-cipher" #:do
    (it-check-aes/core #:plaintext '0x00112233445566778899aabbccddeeff
                       #:key '0x000102030405060708090a0b0c0d0e0f
                       #:ciphertext '0x69c4e0d86a7b0430d8cdb78070b4c55a)
    (it-check-aes/core #:plaintext '0x00112233445566778899aabbccddeeff
                       #:key '0x000102030405060708090a0b0c0d0e0f1011121314151617
                       #:ciphertext '0xdda97ca4864cdfe06eaf70a0ec0d7191)
    (it-check-aes/core #:plaintext '0x00112233445566778899aabbccddeeff
                       #:key '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                       #:ciphertext '0x8ea2b7ca516745bfeafc49904b496089))]

@handbook-scenario[#:tag "aes-ctr"]{Real world example in CTR mode}

The next testcase is dumped from the debug information of @~cite[libssh2].

@tamer-note{aes-ctr-cipher}
@handbook-chunk[<aes-ctr-spec>
  (context "aes-ctr-cipher" #:do
    (it-check-aes/ctr #:plaintext '0x050000000C7373682D75736572617574
                      #:IV '0x409265b173313e3a1c78c714b27bc72c
                      #:key '0x6df8cd5d2a6487aa257dc3e8119a20c1
                      #:ciphertext '0xb1b5681bd3596d80f34482a7a2f215ad))]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module tamer typed/racket
         <aes>

         (spec-begin aes #:do
                     <aes-core-spec!>
                     <aes-core-spec>
                     <aes-ctr-spec>))]

@chunk[<aes>
       (require bitmap)

       (require digimon/format)
       (require digimon/digitama/unsafe/release/ops)

       (require "inc/aes.rkt")
       
       (require "../../digitama/algorithm/crypto/aes/s-box.rkt")
       (require "../../digitama/algorithm/crypto/aes/pretty.rkt")

       (define sbox-gapsize 8)

       (define aes-plaintext '0x3243f6a8885a308d313198a2e0370734)
       (define aes-ciphertext '0x3925841d02dc09fbdc118597196a0b32)

       (define aes-key128 '0x2b7e151628aed2a6abf7158809cf4f3c)
       (define aes-key192 '0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b)
       (define aes-key256 '0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4)
       
       (define state-array-bitmap : (-> Bytes Bitmap)
         (let ([/dev/stdout (open-output-string '/dev/stdout)])
           (lambda [state]
             (state-array-pretty-print state 4 4 #:port /dev/stdout)

             (let ([octets (string-split (bytes->string/latin-1 (get-output-bytes /dev/stdout #true)))])
               (bitmap-frame #:padding 4 #:border (default-stroke)
                             (bitmap-table 4 (map bitmap-text octets)
                                           'cc 'cc 8 8))))))

       (define rotated-schedule-bitmap : (-> (Vectorof Nonnegative-Fixnum) Integer Bitmap)
         (let ([/dev/stdout (open-output-string '/dev/stdout)])
           (lambda [schedule start]
             (define pool (make-bytes 16))

             (integer->integer-bytes (vector-ref schedule (+ start 0)) 4 #false #true pool 00)
             (integer->integer-bytes (vector-ref schedule (+ start 1)) 4 #false #true pool 04)
             (integer->integer-bytes (vector-ref schedule (+ start 2)) 4 #false #true pool 08)
             (integer->integer-bytes (vector-ref schedule (+ start 3)) 4 #false #true pool 12)
             
             (let ([octets (string-split (bytes->hexstring pool #:separator " "))])
               (bitmap-frame #:padding 4 #:border (default-stroke)
                             (bitmap-table 4 (map bitmap-text octets)
                                           'cc 'cc 8 8))))))
       
       (define aes-key-schedule : (-> Symbol Positive-Byte Symbol (Vectorof Nonnegative-Fixnum))
         (lambda [0xkey column 0xlast]
           (define key (assert (symb0x->octets 0xkey)))
           (define last-one (symb0x->number 0xlast))
           
           (printf "Cipher Key = ~a (~a bits)~n" (bytes->hexstring key) (* (bytes-length key) 8))

           (define schedule (aes-key-expand key))
           (define last-word (vector-ref schedule (- (vector-length schedule) 1)))

           ((inst words-pretty-print Nonnegative-Fixnum)
            schedule
            #:column column
            #:port (if (and last-one (= last-word last-one))
                       (current-output-port)
                       (current-error-port)))
           schedule))

       (define aes-add-round-key : (->* (Bytes (Vectorof Nonnegative-Fixnum) Byte) (Byte) Bitmap)
         (lambda [state schedule start [space 3]]
           (define Sin (state-array-bitmap state))

           (aes-state-add-round-key! state schedule start)
           
           (bitmap-hc-append #:gapsize sbox-gapsize
                             (if (> space 0)
                                 (bitmap-hc-append* #:gapsize sbox-gapsize
                                                    (cons Sin (make-list space (bitmap-ghost Sin))))
                                 Sin)
                             (bitmap-text "⊕")
                             (rotated-schedule-bitmap schedule start)
                             (bitmap-text "="))))

       (define aes-round-step : (-> Bytes (Vectorof Nonnegative-Fixnum) Byte Bitmap)
         (lambda [state schedule round]
           (define Sin (state-array-bitmap state))
           
           (aes-state-array-substitute! state aes-substitute-box)
           (define Ssub (state-array-bitmap state))

           (aes-left-shift-rows! state)
           (define Sshift (state-array-bitmap state))

           (aes-mixcolumns! state)
           (bitmap-hc-append #:gapsize sbox-gapsize
                             Sin Ssub Sshift (aes-add-round-key state schedule (unsafe-b* round 4) 0))))

       (define aes-round-done : (-> Bytes (Vectorof Nonnegative-Fixnum) Byte Bitmap)
         (lambda [state schedule round]
           (define Sin (state-array-bitmap state))
           
           (aes-state-array-substitute! state aes-substitute-box)
           (define Ssub (state-array-bitmap state))

           (aes-left-shift-rows! state)
           (bitmap-vl-append #:gapsize sbox-gapsize
                             (bitmap-hc-append #:gapsize sbox-gapsize
                                               Sin Ssub (aes-add-round-key state schedule (unsafe-b* round 4) 1))
                             (state-array-bitmap state))))]
