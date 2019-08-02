# SSH: The Secure Shell Protocol

wargrey

The secure shell \(_SSH_\) Protocol is a protocol for secure remote
login and other secure network services over an insecure network.

This document describes a full-featured client-side and server-side
library named _λsh_ implementing the SSH protocol that wrote in **Typed
Racket** along with minimal **C** extensions.

λsh does not reply on \[OpenSSH\] and \[OpenSSL\], nor plan to stick
with them. They are referenced here for parts of their sources and
interoperability tests.

**Warning:** Meanwhile, λsh is far away from _full-featured_ and may not
work accurately. Everything therefore is subject to change.

---


