#lang scribble/manual

@(require digimon/tamer)

@handbook-title/pkg-desc[]

@;tamer-smart-summary[]

@handbook-smart-table[]

@include-section[(submod "architecture.rkt" doc)]
@include-section[(submod "transport.rkt" doc)]

@handbook-appendix[#:index? #true]