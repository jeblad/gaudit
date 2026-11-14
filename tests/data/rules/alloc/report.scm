(define (report input) (let loop ((acc '())) (loop (cons (make-string 1000 #\x) acc))))
