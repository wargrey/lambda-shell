#lang info

(define collection 'use-pkg-name)

(define pkg-desc "SSH: The Secure Shell Protocol")
(define pkg-authors '(wargrey))

(define software-version 'λsh)

(define version "1.0")

#;(define raco-commands '(["ssh"  ssh/digivice/ssh  "yet another ssh client" #false]
                          ["sshd" ssh/digivice/sshd "yet another ssh server" #false]))

(define scribblings '(["ssh/tamer/SSH.scrbl" (main-doc multi-page) (net-library)]))
