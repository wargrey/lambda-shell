#lang scribble/lp2

@(require digimon/tamer)

@handbook-story{ASN.1 Sequence}

@;tamer-smart-summary[]

@handbook-scenario{Define a Sequence}

@tamer-action[
 (define-asn-sequence x690-example : X690-Example
   ([name : asn-string/ia5 #:default "Smith"]
    [ok : asn-boolean #:optional]))
 (define smith (make-x690-example #:ok #true))
 (define octets (x690-example->bytes smith))
 (bytes->hex-string octets #:separator " ")]

@handbook-reference[]

@; Chunks after `handbook-reference[]` will never be rendered in documents
@; <*> is the main chunk by convention.

@chunk[|<*>|
       (require digimon/tamer)
       (tamer-taming-start!)

       (module+ tamer |<asn.1-der:sequence:*>|)]

@chunk[|<asn.1-der:sequence:*>|
       (module story typed/racket/base
         (require (submod digimon/tamer typed))
         
         <sequence>)]

@chunk[<sequence>
       (require "../../digitama/asn-der/primitive.rkt")
       (require "../../digitama/asn-der/sequence.rkt")]
