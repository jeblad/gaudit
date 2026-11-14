;; SPDX-License-Identifier: GPL-3.0-only
;; Private Files: the report on the collection ("gaudit-orchestrator secrets").
;;
;; Evaluated by gaudit-engine in (ice-9 sandbox): pure bindings only, no I/O.
;; The input is data, never code:
;;
;;   (input (system (host "...") (distro "...") (backend "..."))
;;          (level "quick"|"full")
;;          (collection (secret (path "...") (reason "...") (mode M) (reach R)
;;                              (owned 0|1) (exact 0|1)) ...
;;                      (secrets (status S) (count N) (shown M) (others A)
;;                               (groups B) (truncated 0|1))))
;;
;; quick holds the known places only (Home), full also the search of the
;; whole home folder; a missing level counts as full.
;; reach: 0 only the user, 1 the user's own private group, 2 other groups,
;; 3 every account. The result is a list of report elements; texts are
;; English msgids in the plugin's own text domain (marked G_, and N_ for a
;; singular and plural pair), with {key} placeholders the GUI fills in. A fix names an item of the collection by its position,
;; never a path: the command is built by gAudit from the collected data.

;; --- Reading the input ---------------------------------------------------

(define (field item key)
  (let ((entry (assq key (cdr item))))
    (and entry (cadr entry))))

(define (section-of input key)
  (let ((entry (assq key (cdr input))))
    (if entry (cdr entry) '())))

;; The collection's items with their positions: ((0 . item) (1 . item) ...).
(define (numbered items)
  (let loop ((items items) (n 0) (acc '()))
    (if (null? items)
        (reverse acc)
        (loop (cdr items) (+ n 1) (cons (cons n (car items)) acc)))))

(define (keep pred lst)
  (cond ((null? lst) '())
        ((pred (car lst)) (cons (car lst) (keep pred (cdr lst))))
        (else (keep pred (cdr lst)))))

(define (first-with head items)
  (cond ((null? items) #f)
        ((eq? (car (cdar items)) head) (cdar items))
        (else (first-with head (cdr items)))))

;; --- Building the report -------------------------------------------------

(define (msg text . args) (cons 'msg (cons text args)))
;; forms: (N_ "one" "many"), so xgettext sees the pair.
(define (msgn forms n . args) (cons 'msgn (append forms (cons n args))))

;; What a reason id is called; unknown ids are shown as they are.
(define reasons
  (list (cons "home-writable"       (G_ "Your home folder can be changed by others"))
        (cons "tool-mode"           (G_ "Permissions SSH or GnuPG refuse"))
        (cons "known-secret"        (G_ "Stored passwords or keys"))
        (cons "openssh-private-key" (G_ "SSH private key"))
        (cons "pem-private-key"     (G_ "Private key"))
        (cons "pgp-private-key"     (G_ "PGP private key"))
        (cons "putty-private-key"   (G_ "PuTTY private key"))
        (cons "gnupg-private-key"   (G_ "GnuPG private key"))
        (cons "gnupg1-secret"       (G_ "Old GnuPG secret keyring"))
        (cons "pkcs12"              (G_ "Certificate with private key"))
        (cons "java-keystore"       (G_ "Java keystore"))
        (cons "keepass"             (G_ "KeePass password database"))
        (cons "pass"                (G_ "Password store entry"))
        (cons "gnome-keyring"       (G_ "GNOME keyring"))
        (cons "kwallet"             (G_ "KDE wallet"))
        (cons "browser-passwords"   (G_ "Saved browser passwords"))
        (cons "crypto-wallet"       (G_ "Cryptocurrency wallet"))
        (cons "netrc"               (G_ "Stored logins (.netrc)"))
        (cons "pgpass"              (G_ "PostgreSQL passwords"))
        (cons "mysql-client"        (G_ "MySQL login"))
        (cons "git-credentials"     (G_ "Git passwords"))
        (cons "aws-credentials"     (G_ "AWS keys"))
        (cons "kube-config"         (G_ "Kubernetes credentials"))
        (cons "docker-auth"         (G_ "Docker logins"))
        (cons "github-cli"          (G_ "GitHub login"))
        (cons "rclone"              (G_ "Cloud storage logins (rclone)"))))

(define (reason-text id)
  (let ((entry (assoc id reasons)))
    (if entry (msg (cdr entry)) (list 'text id))))

;; Permission bits as four octal digits, e.g. "0644".
(define (octal mode)
  (let loop ((s (number->string mode 8)))
    (if (< (string-length s) 4) (loop (string-append "0" s)) s)))

(define (shown-path path)
  (if (equal? path ".") "~" (string-append "~/" path)))

;; Secrets only the user (or their own private group) can read are fine.
(define (problem? item) (>= (field item 'reach) 2))

(define (row entry)
  (let* ((n (car entry))
         (item (cdr entry))
         (path (field item 'path))
         (head (list 'row
                     (list 'verdict (if (problem? item) 'warning 'ok))
                     (list 'title (list 'text (shown-path path)))
                     (list 'subtitle (msg (G_ "{kind} · {mode}")
                                          (list 'kind (reason-text (field item 'reason)))
                                          (list 'mode (octal (field item 'mode))))))))
    (if (problem? item)
        (append head (list (list 'fix (if (equal? path ".") 'close-home 'make-private)
                                 (list 'item n))))
        head)))

;; A section for the findings whose reach is in reaches, or nothing.
(define (section entries reaches title description)
  (let ((mine (keep (lambda (e) (memv (field (cdr e) 'reach) reaches)) entries)))
    (if (null? mine)
        '()
        (cons (list 'section (list 'title (msg title)) (list 'description (msg description)))
              (map row mine)))))

(define (verdict summary)
  (cond ((not (= (field summary 'status) 0)) 'unknown)
        ((> (+ (field summary 'others) (field summary 'groups)) 0) 'warning)
        ((= (field summary 'truncated) 1) 'unknown)
        (else 'ok)))

(define (quick? input)
  (equal? (section-of input 'level) '("quick")))

(define (head summary quick)
  (let* ((v (verdict summary))
         (count (field summary 'count))
         (reachable (+ (field summary 'others) (field summary 'groups)))
         (title
          (cond ((eq? v 'warning)
                 (msgn (N_ "{n} secret can be read by others"
                           "{n} secrets can be read by others")
                       reachable (list 'n reachable)))
                ((and (eq? v 'ok) quick)
                 (msg (G_ "The usual places for secrets are closed")))
                ((and (eq? v 'ok) (= count 0))
                 (msg (G_ "No secrets found outside the usual places")))
                ((eq? v 'ok)
                 (msgn (N_ "{n} secret found, only you can read it"
                           "{n} secrets found, only you can read them")
                       count (list 'n count)))
                ((= (field summary 'status) 0)
                 (msg (G_ "The search stopped before the end")))
                (else (msg (G_ "Your home folder could not be searched")))))
         (description
          (cond ((and quick (not (eq? v 'unknown)))
                 (msg (G_ "Only the places where programs usually keep secrets were checked. The thorough report searches your whole home folder.")))
                ((eq? v 'ok)
                 (msg (G_ "Secrets only you can read are normal. This means none were found that others can read, not that every secret was found.")))
                ((eq? v 'warning)
                 (msg (G_ "Anyone who can use these accounts can copy them. Open each one marked with a warning to see how to close it.")))
                (else (msg (G_ "Nothing is known about the files that were not searched."))))))
    (list 'report (list 'verdict v) (list 'title title) (list 'description description))))

(define (notes summary)
  (append
   (if (< (field summary 'shown) (field summary 'count))
       (list (list 'note (msg (G_ "Showing {shown} of {count} files.")
                              (list 'shown (field summary 'shown))
                              (list 'count (field summary 'count)))))
       '())
   (if (= (field summary 'truncated) 1)
       (list (list 'note (msg (G_ "Your home folder has more files than the search goes through, so it stopped before the end."))))
       '())))

(define (report input)
  (let* ((entries (numbered (section-of input 'collection)))
         (summary (first-with 'secrets entries))
         (findings (keep (lambda (e) (eq? (car (cdr e)) 'secret)) entries)))
    (if (not summary)
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Your home folder could not be searched")))
                    (list 'description (msg (G_ "Nothing is known about the files that were not searched.")))))
        (append
         (list (head summary (quick? input)))
         (section findings '(3) (G_ "Every account can read these")
                  (G_ "Any other account on this computer can read them, including programs running as those accounts."))
         (section findings '(2) (G_ "Members of a group can read these")
                  (G_ "Accounts in a group that has access to the file, or to a folder on the way, can read them."))
         (section findings '(0 1) (G_ "Only you can read these")
                  (G_ "This is how secrets should be kept. Listed so you know where they are."))
         (notes summary)))))
