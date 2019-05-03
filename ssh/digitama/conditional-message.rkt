#lang racket/base

;;; WARNING: Require a typed module for syntax may cause "namespace mismatch" error

(provide (all-defined-out))
(provide (for-syntax (all-defined-out)))

(require (for-syntax racket/base))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-for-syntax ssh-message-hidden-fields-count 2)

(define-for-syntax (ssh-field-index <key> <fields>)
  (define key (syntax->datum <key>))

  (let search-key ([fields (syntax->datum <fields>)]
                   [index ssh-message-hidden-fields-count])
    (cond [(null? fields) (raise-syntax-error 'ssh-field-index "no such field" <key> #false (syntax-e <fields>))]
          [(eq? key (car fields)) (datum->syntax <key> index)]
          [else (search-key (cdr fields) (+ index 1))])))

(define-for-syntax (ssh-case-message-fields <number> <fields> <Types> <defvals> <index>)
  (define index (syntax-e <index>))
  (cons (syntax-e <number>)
        (for/list ([field (in-list (syntax->datum <fields>))]
                   [type (in-list (syntax->datum <Types>))]
                   [defval (in-list (syntax->datum <defvals>))]
                   [idx (in-naturals ssh-message-hidden-fields-count)])
          (list* field type
                 (cond [(= idx index) (list (void))]
                       [else defval])))))

(define-for-syntax (ssh-case-message-shared-fields db <id> <case-val>)
  (define name (syntax-e <id>))
  (define field-infos (hash-ref db name (λ [] null)))
  
  (when (null? field-infos)
    (raise-syntax-error 'ssh-restore-case-message-fields
                        (format "not a case message: ~a" name)
                        <id>))
    
  (cons (car field-infos)
          (for/list ([field-info (in-list (cdr field-infos))])
            (list* (datum->syntax <id> (car field-info))
                   (datum->syntax <id> (cadr field-info))
                   (let ([defvals (cddr field-info)])
                     (cond [(null? defvals) null]
                           [(void? (car defvals)) (list <case-val>)]
                           [else (datum->syntax <case-val> defvals)]))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define ssh-case-message-field-database (make-hasheq))
