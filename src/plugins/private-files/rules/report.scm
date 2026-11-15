;; SPDX-License-Identifier: GPL-3.0-only
;; Private Files: the report on the collection ("gaudit-orchestrator secrets").
;;
;; Evaluated by gaudit-engine in (ice-9 sandbox): pure bindings only, no I/O.
;; The input is data, never code:
;;
;;   (input (system (host "...") (distro "...") (backend "..."))
;;          (level "quick"|"full")
;;          (collection (area (index I) (path "...") (status S) (remote 0|1) (exact 0|1)) ...
;;                      (area-stats (index I) (entries N) (seconds T) (truncated 0|1) (caches C)) ...
;;                      (read-limit (bytes N))
;;                      (secret (area I) (path "...") (reason "...") (mode M) (reach R)
;;                              (owned 0|1) (exact 0|1)) ...
;;                      (secrets (status S) (count N) (shown M) (others A)
;;                               (groups B) (truncated 0|1))))
;;
;; quick holds the known places only (Home), full also the search of the
;; whole home folder and of the folders the user added; a missing level
;; counts as full. Area 0 is the home folder; a finding's path is relative
;; to its area. status: 0 searched, 1 could not be searched, 2 overlaps an
;; area already searched. Findings on a network folder (remote) are
;; uncertain: modes and owners there may not say who can reach a file.
;; reach: 0 only the user, 1 the user's own private group, 2 other groups,
;; 3 every account. The result is a list of report elements; texts are
;; English msgids in the plugin's own text domain (marked G_, and N_ for a
;; singular and plural pair), with {key} placeholders the GUI fills in. A fix names an item of the collection by its position,
;; never a path: the command is built by gAudit from the collected data.

;; --- Reading the input ---------------------------------------------------

(define (field item key)
  (let ((entry (assq key (cdr item))))
    (and entry (cadr entry))))

;; A count that may be missing (a collection from before a field was
;; added): 0, so one note cannot cost the whole report.
(define (count-field item key)
  (let ((v (field item key)))
    (if (number? v) v 0)))

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

;; --- Areas --------------------------------------------------------------

(define (area-of areas index)
  (cond ((null? areas) #f)
        ((= (field (car areas) 'index) index) (car areas))
        (else (area-of (cdr areas) index))))

(define (remote? areas item)
  (let ((a (area-of areas (field item 'area))))
    (and a (= (field a 'remote) 1))))

(define (shown-path areas item)
  (let ((path (field item 'path))
        (a (area-of areas (field item 'area))))
    (cond ((and (= (field item 'area) 0) (equal? path ".")) "~")
          ((= (field item 'area) 0) (string-append "~/" path))
          (a (string-append (field a 'path) "/" path))
          (else path))))

;; --- Findings -------------------------------------------------------------

;; Secrets only the user (or their own private group) can read are fine.
(define (problem? item) (>= (field item 'reach) 2))

(define (row areas entry)
  (let* ((n (car entry))
         (item (cdr entry))
         (far (remote? areas item))
         (bad (problem? item))
         (head (list 'row
                     (list 'verdict (cond ((and bad far) 'unknown) (bad 'warning) (else 'ok)))
                     (list 'title (list 'text (shown-path areas item)))
                     (list 'subtitle
                           (msg (if (and bad far)
                                    (G_ "{kind} · {mode} · on a network folder")
                                    (G_ "{kind} · {mode}"))
                                (list 'kind (reason-text (field item 'reason)))
                                (list 'mode (octal (field item 'mode))))))))
    (if bad
        (append head (list (list 'fix (if (and (= (field item 'area) 0)
                                               (equal? (field item 'path) "."))
                                          'close-home 'make-private)
                                 (list 'item n))))
        head)))

;; A section for the findings pred keeps, or nothing.
(define (section areas entries pred title description)
  (let ((mine (keep (lambda (e) (pred (cdr e))) entries)))
    (if (null? mine)
        '()
        (cons (list 'section (list 'title (msg title)) (list 'description (msg description)))
              (map (lambda (e) (row areas e)) mine)))))

(define (count-of pred entries)
  (length (keep (lambda (e) (pred (cdr e))) entries)))

;; Reachable on a network folder only: not known for sure.
(define (verdict summary far-problems)
  (let ((reachable (+ (field summary 'others) (field summary 'groups))))
    (cond ((not (= (field summary 'status) 0)) 'unknown)
          ((> (- reachable far-problems) 0) 'warning)
          ((> far-problems 0) 'unknown)
          ((= (field summary 'truncated) 1) 'unknown)
          (else 'ok))))

(define (quick? input)
  (equal? (section-of input 'level) '("quick")))

(define (head summary quick far-problems)
  (let* ((v (verdict summary far-problems))
         (count (field summary 'count))
         (reachable (- (+ (field summary 'others) (field summary 'groups)) far-problems))
         (title
          (cond ((eq? v 'warning)
                 (msgn (N_ "{n} secret can be read by others"
                           "{n} secrets can be read by others")
                       reachable (list 'n reachable)))
                ((and (> far-problems 0) (= (field summary 'status) 0))
                 (msgn (N_ "{n} secret on a network folder may be readable by others"
                           "{n} secrets on network folders may be readable by others")
                       far-problems (list 'n far-problems)))
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
                ((> far-problems 0)
                 (msg (G_ "On a network folder the server decides who can read a file, and what this computer shows may not say so. Check them on the server.")))
                (else (msg (G_ "Nothing is known about the files that were not searched."))))))
    (list 'report (list 'verdict v) (list 'title title) (list 'description description))))

(define (area-notes areas)
  (map (lambda (a)
         (let ((path (list 'path (field a 'path))))
           (list 'note
                 (case (field a 'status)
                   ((0) (msg (G_ "Also searched: {path}") path))
                   ((2) (msg (G_ "Not searched again, it overlaps a folder already searched: {path}") path))
                   (else (msg (G_ "Could not be searched: {path}") path))))))
       ;; Every area but the home folder itself: added ones searched, and
       ;; those not searched (they carry index 0).
       (keep (lambda (a) (or (> (field a 'index) 0) (not (= (field a 'status) 0)))) areas)))

;; How each folder's search went (full collection): the one where it
;; stopped at the limit is named, and so is a large or slow one, which the
;; user may want off the list. The thresholds are a judgement, so here.
(define large-entries 250000)
(define slow-seconds 600)

(define (stats-notes areas stats)
  (define (where s)
    (let ((a (area-of areas (field s 'index))))
      (cond ((= (field s 'index) 0) "~")
            (a (field a 'path))
            (else "?"))))
  (apply append
         (map (lambda (s)
                (let ((path (list 'path (where s)))
                      (n (field s 'entries))
                      (minutes (quotient (+ (field s 'seconds) 59) 60)))
                  (cond ((= (field s 'truncated) 1)
                         (list (list 'note (msg (G_ "{path} has more files than the search goes through, so it stopped there.") path))))
                        ((and (> (field s 'index) 0)
                              (or (>= n large-entries) (>= (field s 'seconds) slow-seconds)))
                         (list (list 'note (msg (G_ "{path} is large: {entries} files and folders, {minutes} min. Take it off the list if it need not be checked every time.")
                                                path (list 'entries n) (list 'minutes minutes)))))
                        (else '()))))
              stats)))

;; Said when the user chose another read limit than the default.
(define default-read-limit 65536)

;; Caches left out (unless the user asked for them): how many, in all.
(define (caches-notes stats)
  (let ((n (apply + (map (lambda (s) (count-field s 'caches)) stats))))
    (if (> n 0)
        (list (list 'note (msgn (N_ "{n} cache folder was not checked."
                                    "{n} cache folders were not checked.")
                                n (list 'n n))))
        '())))

(define (read-limit-notes entries)
  (let ((r (first-with 'read-limit entries)))
    (if (and r (not (= (field r 'bytes) default-read-limit)))
        (list (list 'note (msg (G_ "Files over {size} KiB were recognised by name only.")
                               (list 'size (quotient (field r 'bytes) 1024)))))
        '())))

(define (notes summary stats shown-problems)
  (let ((shown (list 'shown (field summary 'shown)))
        (count (list 'count (field summary 'count)))
        (reachable (+ (field summary 'others) (field summary 'groups))))
    (append
     ;; Those others can reach come first, so when all of them are shown,
     ;; the rest are only the user's: say so, not just that some are missing.
     (cond ((not (< (field summary 'shown) (field summary 'count))) '())
           ((>= shown-problems reachable)
            (list (list 'note (msg (G_ "Showing {shown} of the {count} secrets found. Those not shown can only be read by you.")
                                   shown count))))
           (else
            (list (list 'note (msg (G_ "Showing {shown} of the {count} secrets found. Some that others can read are not shown: fix these first, then check again.")
                                   shown count)))))
     ;; Without stats (an older collection), the stop is still said.
     (if (and (null? stats) (= (field summary 'truncated) 1))
         (list (list 'note (msg (G_ "Your home folder has more files than the search goes through, so it stopped before the end."))))
         '()))))

(define (report input)
  (let* ((entries (numbered (section-of input 'collection)))
         (summary (first-with 'secrets entries))
         (areas (map cdr (keep (lambda (e) (eq? (car (cdr e)) 'area)) entries)))
         ;; Not searched areas keep index 0 in their line; only searched ones
         ;; are areas findings belong to.
         (searched (keep (lambda (a) (= (field a 'status) 0)) areas))
         (findings (keep (lambda (e) (eq? (car (cdr e)) 'secret)) entries))
         (stats (map cdr (keep (lambda (e) (eq? (car (cdr e)) 'area-stats)) entries)))
         (far (lambda (item) (and (problem? item) (remote? searched item))))
         (far-problems (count-of far findings)))
    (if (not summary)
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Your home folder could not be searched")))
                    (list 'description (msg (G_ "Nothing is known about the files that were not searched.")))))
        (append
         (list (head summary (quick? input) far-problems))
         (section searched findings
                  (lambda (i) (and (= (field i 'reach) 3) (not (far i))))
                  (G_ "Every account can read these")
                  (G_ "Any other account on this computer can read them, including programs running as those accounts."))
         (section searched findings
                  (lambda (i) (and (= (field i 'reach) 2) (not (far i))))
                  (G_ "Members of a group can read these")
                  (G_ "Accounts in a group that has access to the file, or to a folder on the way, can read them."))
         (section searched findings far
                  (G_ "On network folders, perhaps readable by others")
                  (G_ "This computer shows them as readable by others, but on a network folder the server decides."))
         (section searched findings (lambda (i) (< (field i 'reach) 2))
                  (G_ "Only you can read these")
                  (G_ "This is how secrets should be kept. Listed so you know where they are."))
         (area-notes areas)
         (stats-notes searched stats)
         (read-limit-notes entries)
         (caches-notes stats)
         (notes summary stats (count-of problem? findings))))))
