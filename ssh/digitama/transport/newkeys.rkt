#lang typed/racket/base

(provide (all-defined-out))

(struct ssh-newkeys
  ([session-id : Bytes]
   [c2s-inflate : (Option (-> Bytes Bytes))]
   [s2c-inflate : (Option (-> Bytes Bytes))]
   [c2s-deflate : (Option (-> Bytes Bytes))]
   [s2c-deflate : (Option (-> Bytes Bytes))]
   [c2s-encrypt : (-> Bytes Bytes)]
   [s2c-encrypt : (-> Bytes Bytes)]
   [c2s-decrypt : (-> Bytes Bytes)]
   [s2c-decrypt : (-> Bytes Bytes)]
   [c2s-mac : (-> Bytes Bytes)]
   [s2c-mac : (-> Bytes Bytes)]
   [c2s-mac-size : Index]
   [s2c-mac-size : Index])
  #:transparent
  #:type-name SSH-Newkeys)
