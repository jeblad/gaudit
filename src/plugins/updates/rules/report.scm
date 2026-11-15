;; SPDX-License-Identifier: GPL-3.0-only
;; Updates: the report on the collection ("gaudit-orchestrator updates").
;;
;; Evaluated by gaudit-engine in (ice-9 sandbox): pure bindings only, no I/O.
;; The input is data, never code:
;;
;;   (input (system (host "...") (distro "...") (backend "..."))
;;          (level "quick"|"full")
;;          (collection (fact (key "check-days") (status S) (value N) (text "...")) ...
;;                      (facts (count N))
;;                      [(integrity-file (kind K) (package "...") (path "...")) ...
;;                       (integrity (verdict V) (packages N) (files N) (checked N)
;;                                  (changed N) (missing N) (unreadable N) (excluded N)
;;                                  (diverted N) (bad-lines N) (megabytes N) (shown N)
;;                                  (seconds N))]))
;;
;; The integrity lines come from the helper, at Thorough and in the full
;; report only: every package file compared with dpkg's checksum. kind: 0
;; changed, 1 missing, 2 could not be read; at most 40 are listed.
;;
;; status: 0 known, 1 could not be found out, 2 not supported on this
;; system, 3 does not apply here. The keys are listed in common/updates.h.
;; Facts only come in; what is a warning is decided here, and nowhere else.
;; The report is grouped by what can go wrong, so each problem leads to its
;; own fix: looking for updates, installing them, where security updates
;; come from, software no source keeps up to date, package systems not
;; checked. Whether an admin tool (Software Updater, Synaptic, ...) is used
;; is not judged here: its own plugin does that.
;;
;; Texts are English msgids in the plugin's own text domain (G_, and N_ for
;; a singular and plural pair), with {key} placeholders the GUI fills in. A
;; fix names an item of the collection by its position, never a command.

;; --- Reading the input ---------------------------------------------------

(define (field item key)
  (let ((entry (assq key (cdr item))))
    (and entry (cadr entry))))

(define (section-of input key)
  (let ((entry (assq key (cdr input))))
    (if entry (cdr entry) '())))

(define (numbered items)
  (let loop ((items items) (n 0) (acc '()))
    (if (null? items)
        (reverse acc)
        (loop (cdr items) (+ n 1) (cons (cons n (car items)) acc)))))

;; The fact with this key as (position . item), or #f.
(define (fact entries key)
  (cond ((null? entries) #f)
        ((and (eq? (car (cdar entries)) 'fact)
              (equal? (field (cdar entries) 'key) key))
         (car entries))
        (else (fact (cdr entries) key))))

(define (status-of f) (if f (field (cdr f) 'status) 2))
(define (known? f) (= (status-of f) 0))
(define (unknown? f) (= (status-of f) 1))
(define (value f) (field (cdr f) 'value))
(define (text-of f) (field (cdr f) 'text))
(define (item-of f) (car f))

(define (keep pred lst)
  (cond ((null? lst) '())
        ((pred (car lst)) (cons (car lst) (keep pred (cdr lst))))
        (else (keep pred (cdr lst)))))

;; --- Building the report -------------------------------------------------

(define (msg text . args) (cons 'msg (cons text args)))
(define (msgn forms n . args) (cons 'msgn (append forms (cons n args))))

(define day (* 24 60 60))

;; Updates not looked for in longer than this is a warning (as Home's
;; probe has it).
(define index-max-age (* 7 day))

;; Without automatic installation, updates waiting while nothing has been
;; installed for longer than this is a warning.
(define stale-after (* 14 day))

;; A row; fix: #f or (id . fact) for (fix ID (item N)).
(define (row verdict title subtitle fix)
  (append (list 'row (list 'verdict verdict) (list 'title title) (list 'subtitle subtitle))
          (if fix (list (list 'fix (car fix) (list 'item (item-of (cdr fix))))) '())))

(define (section title description rows)
  (let ((rows (keep (lambda (r) r) rows)))
    (if (null? rows)
        '()
        (cons (list 'section (list 'title (msg title)) (list 'description (msg description)))
              rows))))

(define (ago seconds)
  (let ((days (quotient seconds day)))
    (cond ((< seconds (* 2 60 60)) (msg (G_ "less than two hours ago")))
          ((< seconds day) (msgn (N_ "{n} hour ago" "{n} hours ago")
                                 (quotient seconds 3600) (list 'n (quotient seconds 3600))))
          (else (msgn (N_ "{n} day ago" "{n} days ago") days (list 'n days))))))

(define (unknown-row title)
  (row 'unknown (msg title) (msg (G_ "Could not be found out")) #f))

;; Never left out: updates matter too much to disappear silently. Not the
;; same as unknown ("could not find out"), but not known either.
(define (unsupported? f) (= (status-of f) 2))
(define (unsupported-row title)
  (row 'unknown (msg title) (msg (G_ "Not supported on this system yet")) #f))

;; --- Looking for updates --------------------------------------------------

(define (check-days-row f)
  (cond ((unknown? f) (unknown-row (G_ "How often updates are looked for")))
        ((unsupported? f) (unsupported-row (G_ "How often updates are looked for")))
        ((not (known? f)) #f)
        ((= (value f) 0)
         (row 'warning (msg (G_ "Updates are never looked for"))
              (msg (G_ "Nothing new is found, security updates included"))
              (cons 'check-on f)))
        ((= (value f) 1)
         (row 'ok (msg (G_ "Updates are looked for every day")) (msg (G_ "Set up as it should be")) #f))
        (else
         (row 'ok (msgn (N_ "Updates are looked for every {n} day"
                            "Updates are looked for every {n} days")
                        (value f) (list 'n (value f)))
              (msg (G_ "Set up as it should be")) #f))))

(define (check-timer-row f days)
  (and (known? f) (= (value f) 0)
       ;; Only matters when looking is set up at all.
       (not (and (known? days) (= (value days) 0)))
       (row 'warning (msg (G_ "The daily job that looks for updates is off"))
            (msg (G_ "Whatever the settings say, nothing looks for updates"))
            (cons 'timers f))))

(define (index-row f)
  (cond ((unknown? f) (unknown-row (G_ "When updates were last looked for")))
        ((not (known? f)) #f)
        ((> (value f) index-max-age)
         (row 'warning (msg (G_ "Updates were last looked for {when}") (list 'when (ago (value f))))
              (msg (G_ "Updates published since then are not known here"))
              (cons 'look-now f)))
        ;; Recent enough: no row of its own; it says how fresh the status is
        ;; (security-row's subtitle).
        (else #f)))

;; --- Installing updates ---------------------------------------------------

(define (install-row f timer last own)
  (cond ((unknown? f) (unknown-row (G_ "Whether updates are installed automatically")))
        ((unsupported? f) (unsupported-row (G_ "Whether updates are installed automatically")))
        ((not (known? f)) #f)
        ((= (value f) 1)
         (cond ((and (known? timer) (= (value timer) 0))
                (row 'warning (msg (G_ "The daily job that installs updates is off"))
                     (msg (G_ "Automatic installation is set up, but never runs"))
                     (cons 'timers timer)))
               ;; Set up by gAudit: its page can take it away again.
               ((and (known? own) (= (value own) 1))
                (row 'ok (msg (G_ "Updates are installed automatically"))
                     (msg (G_ "Set up by gAudit")) (cons 'automatic-on f)))
               ((and (known? last) (< (value last) 0))
                (row 'ok (msg (G_ "Updates are installed automatically"))
                     (msg (G_ "Not run yet")) #f))
               ((known? last)
                (row 'ok (msg (G_ "Updates are installed automatically"))
                     (msg (G_ "Last run {when}") (list 'when (ago (value last)))) #f))
               (else
                (row 'ok (msg (G_ "Updates are installed automatically")) (msg (G_ "Set up as it should be")) #f))))
        ;; A recommendation, not a warning: there may be a reason it is off,
        ;; so no nagging. What waits is judged on its own (security-row,
        ;; pending-row).
        (else
         (row 'advice (msg (G_ "Updates are not installed automatically"))
              (msg (G_ "Recommended: let them install by themselves, unless there is a reason not to"))
              (cons 'automatic-on f)))))

(define (security-row f index)
  (cond ((unknown? f) (unknown-row (G_ "Security updates waiting")))
        ((not (known? f)) #f)
        ((= (value f) 0)
         (row 'ok (msg (G_ "No security updates are waiting"))
              (if (known? index)
                  (msg (G_ "Looked for {when}") (list 'when (ago (value index))))
                  (msg (G_ "As far as the last look for updates knows")))
              #f))
        ;; Always a warning, automatic installation or not.
        (else
         (row 'warning (msgn (N_ "{n} security update is waiting" "{n} security updates are waiting")
                             (value f) (list 'n (value f)))
              (msg (G_ "Until installed, the problems they fix stay open"))
              (cons 'install-now f)))))

;; Nothing installs them automatically, and no package has changed for
;; longer than stale-after: the computer is not kept up to date.
(define (stale? install change)
  (and (known? install) (= (value install) 0)
       (known? change) (> (value change) stale-after)))

(define (pending-row f security install change)
  (let ((days (and (known? change) (quotient (value change) day))))
    (define (waiting n one many)
      (if (stale? install change)
          (row 'warning (msgn (list one many) n (list 'n n))
               (msgn (N_ "Nothing has been installed for {days} day, and nothing installs them automatically"
                         "Nothing has been installed for {days} days, and nothing installs them automatically")
                     days (list 'days days))
               (cons 'install-now f))
          #f))
    (cond ((unknown? f) (unknown-row (G_ "Updates waiting")))
          ((not (known? f)) #f)
          ((known? security)
           (let ((others (- (value f) (value security))))
             (and (> others 0)
                  (or (waiting others "{n} other update is waiting" "{n} other updates are waiting")
                      (row 'ok (msgn (N_ "{n} other update is waiting" "{n} other updates are waiting")
                                     others (list 'n others))
                           (msg (G_ "Not security updates; install them when it suits you")) #f)))))
          ;; Security updates cannot be told apart here: any of them may be one.
          ((= (value f) 0)
           (row 'ok (msg (G_ "No updates are waiting")) (msg (G_ "As far as the last look for updates knows")) #f))
          (else
           (or (waiting (value f) "{n} update is waiting" "{n} updates are waiting")
               (row 'ok (msgn (N_ "{n} update is waiting" "{n} updates are waiting")
                              (value f) (list 'n (value f)))
                    (msg (G_ "Some may be security updates; install them soon")) #f))))))

;; --- Where security updates come from --------------------------------------

(define (source-row official mirror)
  (cond ((or (unknown? official) (unknown? mirror))
         (unknown-row (G_ "Where security updates come from")))
        ((not (known? mirror)) #f)
        ((> (value mirror) 0)
         (row 'warning (msg (G_ "Security updates come from a mirror"))
              (msg (G_ "{host} may lag behind the distribution") (list 'host (text-of mirror)))
              (cons 'mirror mirror)))
        (else
         (row 'ok (msg (G_ "Security updates come from the distribution itself"))
              (msg (G_ "Not from a mirror that may lag behind")) #f))))

;; --- Software no source keeps up to date ------------------------------------

(define (sourceless-rows total above leftover other)
  (define (group f one many subtitle)
    (and (known? f) (> (value f) 0)
         (row 'warning (msgn (list one many) (value f) (list 'n (value f)))
              (msg subtitle) (cons 'sourceless f))))
  (cond ((unknown? total) (list (unknown-row (G_ "Installed software without a source"))))
        ((not (known? total)) '())
        ((= (value total) 0)
         (list (row 'ok (msg (G_ "All installed packages come from a software source"))
                    (msg (G_ "So they get updates")) #f)))
        ((not (known? above))
         (list (row 'warning (msgn (N_ "{n} package gets no updates" "{n} packages get no updates")
                                   (value total) (list 'n (value total)))
                    (msg (G_ "No software source offers them")) (cons 'sourceless total))))
        (else
         (list (group above "{n} package is newer than its software source"
                      "{n} packages are newer than their software source"
                      (G_ "No update reaches them until the source passes that version"))
               (group leftover "{n} package is probably left over from an older release"
                      "{n} packages are probably left over from an older release"
                      (G_ "The distribution no longer offers them"))
               (group other "{n} package probably comes from other places"
                      "{n} packages probably come from other places"
                      (G_ "Such as a downloaded package or a source no longer set up"))))))

;; The pairs above, so xgettext sees them.
(define sourceless-msgids
  (list (N_ "{n} package is newer than its software source"
            "{n} packages are newer than their software source")
        (N_ "{n} package is probably left over from an older release"
            "{n} packages are probably left over from an older release")
        (N_ "{n} package probably comes from other places"
            "{n} packages probably come from other places")))

;; --- Package files ----------------------------------------------------------

;; The first item with this head as (position . item), or #f.
(define (first-item entries head)
  (cond ((null? entries) #f)
        ((eq? (car (cdar entries)) head) (car entries))
        (else (first-item (cdr entries) head))))

(define (ifield e key) (field (cdr e) key))

;; One fix page for them all: reinstalling puts the packages' own files
;; back, so every changed or missing file leads to the same page.
(define (integrity-rows entries)
  (let ((summary (first-item entries 'integrity))
        (files (keep (lambda (e) (eq? (car (cdr e)) 'integrity-file)) entries)))
    (define (fix) (cons 'reinstall summary))
    (define (file-row e)
      (let ((kind (ifield e 'kind)))
        (row (if (= kind 2) 'unknown 'warning)
             (list 'text (ifield e 'path))
             (msg (case kind
                    ((0) (G_ "Changed · {package}"))
                    ((1) (G_ "Missing · {package}"))
                    (else (G_ "Could not be read · {package}")))
                  (list 'package (ifield e 'package)))
             (and (< kind 2) (fix)))))
    (if (not summary)
        '()
        (let ((changed (ifield summary 'changed)) (missing (ifield summary 'missing))
              (unreadable (ifield summary 'unreadable)))
          (append
           (cond ((> (+ changed missing) 0)
                  (list (row 'warning
                             (msgn (N_ "{n} package file was changed or is missing"
                                       "{n} package files were changed or are missing")
                                   (+ changed missing) (list 'n (+ changed missing)))
                             (msg (G_ "Nothing should change installed files, though it may be harmless"))
                             (fix))))
                 ((> unreadable 0)
                  (list (row 'unknown
                             (msgn (N_ "{n} package file could not be read"
                                       "{n} package files could not be read")
                                   unreadable (list 'n unreadable))
                             (msg (G_ "Nothing is known about those files")) #f)))
                 (else
                  (list (row 'ok (msg (G_ "No changed package files found"))
                             (msg (G_ "{files} files from {packages} packages compared")
                                  (list 'files (ifield summary 'checked))
                                  (list 'packages (ifield summary 'packages)))
                             #f))))
           (map file-row files))))))

(define (integrity-notes entries)
  (let ((summary (first-item entries 'integrity)))
    (if (not summary)
        '()
        (let ((found (+ (ifield summary 'changed) (ifield summary 'missing)
                        (ifield summary 'unreadable))))
          (append
           (list (list 'note (msg (G_ "Package files: {files} files from {packages} packages ({megabytes} MB) compared in {seconds} s. No changes found means none were found, not that the computer is proven clean.")
                                  (list 'files (ifield summary 'checked))
                                  (list 'packages (ifield summary 'packages))
                                  (list 'megabytes (ifield summary 'megabytes))
                                  (list 'seconds (ifield summary 'seconds)))))
           (if (< (ifield summary 'shown) found)
               (list (list 'note (msg (G_ "Showing {shown} of the {found} package files found.")
                                      (list 'shown (ifield summary 'shown)) (list 'found found))))
               '())
           (if (> (ifield summary 'bad-lines) 0)
               (list (list 'note (msgn (N_ "{n} line in dpkg's lists of checksums could not be read."
                                           "{n} lines in dpkg's lists of checksums could not be read.")
                                       (ifield summary 'bad-lines)
                                       (list 'n (ifield summary 'bad-lines)))))
               '()))))))

;; --- Package systems ------------------------------------------------------

(define (systems-rows expected others)
  (list (and (known? expected) (= (value expected) 1)
             (row 'warning (msg (G_ "The package system this system should have was not found"))
                  (msg (G_ "Expected {system}, so updates cannot be checked here")
                       (list 'system (text-of expected)))
                  #f))
        (and (known? others) (> (value others) 0)
             (row 'warning (msgn (N_ "Packages from {n} other package system are not checked"
                                     "Packages from {n} other package systems are not checked")
                                 (value others) (list 'n (value others)))
                  (list 'text (text-of others))
                  (cons 'other-systems others)))))

;; --- The whole --------------------------------------------------------------

(define (row-verdict r) (cadr (cadr r)))
(define (row-title r) (cadr (caddr r)))
(define (row-subtitle r) (cadr (cadddr r)))

(define (home verdict title subtitle)
  (list 'home (list 'verdict verdict) (list 'title title) (list 'subtitle subtitle)))

;; Home's condensate: one row per problem, each already a summary; the
;; packages without a source as one, where the first of them is. Nothing
;; for what is right, unless nothing fails: then one row that says so.
(define (home-rows all sourceless-problems total ok-title)
  (define (as-home r) (home (row-verdict r) (row-title r) (row-subtitle r)))
  (define summary
    (if (known? total)
        (home 'warning
              (msgn (N_ "{n} package gets no updates" "{n} packages get no updates")
                    (value total) (list 'n (value total)))
              (msg (G_ "No software source offers them")))
        #f))
  (let loop ((rows all) (seen #f) (acc '()))
    (cond ((null? rows)
           (if (null? acc)
               (list (home 'ok ok-title (msg (G_ "Nothing needs attention"))))
               (reverse acc)))
          ((memq (row-verdict (car rows)) '(ok advice)) (loop (cdr rows) seen acc))
          ((and summary (memq (car rows) sourceless-problems))
           (loop (cdr rows) #t (if seen acc (cons summary acc))))
          (else (loop (cdr rows) seen (cons (as-home (car rows)) acc))))))

(define (report input)
  (let* ((entries (numbered (section-of input 'collection)))
         (get (lambda (key) (fact entries key)))
         (days (get "check-days")) (check-timer (get "check-timer"))
         (index (get "index-age")) (install (get "install"))
         (install-timer (get "install-timer")) (last (get "last-install"))
         (change (get "last-change")) (own (get "own-setting"))
         (pending (get "pending")) (security (get "pending-security"))
         (official (get "security-official")) (mirror (get "security-mirror"))
         (total (get "sourceless")) (above (get "sourceless-above"))
         (leftover (get "sourceless-leftover")) (other (get "sourceless-other"))
         (expected (get "expected-missing")) (others (get "other-systems"))
         ;; The most important first: the title names the first warning.
         ;; Two questions, not apt's two steps: is it up to date now, and
         ;; does it keep itself up to date. Then where updates come from.
         (now (list (security-row security index)
                    (pending-row pending security install change)
                    (index-row index)))
         (setup (list (check-days-row days) (check-timer-row check-timer days)
                      (install-row install install-timer last own)))
         (source (list (source-row official mirror)))
         (sourceless (sourceless-rows total above leftover other))
         (systems (systems-rows expected others))
         (files (integrity-rows entries))
         ;; Only the summary of the package files counts; the files are its detail.
         (files-head (if (pair? files) (list (car files)) '()))
         (all (keep (lambda (r) r)
                    ;; A missing package system first: nothing else can be checked then.
                    (append (list (car systems)) now setup source sourceless
                            files-head (cdr systems))))
         (warnings (keep (lambda (r) (eq? (row-verdict r) 'warning)) all))
         (unknowns (keep (lambda (r) (eq? (row-verdict r) 'unknown)) all))
         (sourceless-problems
          (keep (lambda (r) (and r (eq? (row-verdict r) 'warning))) sourceless))
         (verdict (cond ((pair? warnings) 'warning) ((pair? unknowns) 'unknown)
                        ((null? all) 'unknown) (else 'ok)))
         (ok-title (if (and (known? install) (= (value install) 1))
                       (msg (G_ "Updates are looked for and installed automatically"))
                       (msg (G_ "Updates are looked for regularly"))))
         (title (cond ((pair? warnings)
                       (msgn (N_ "{n} problem with updates" "{n} problems with updates")
                             (length warnings) (list 'n (length warnings))))
                      ((pair? unknowns) (msg (G_ "Not everything about updates could be found out")))
                      ((null? all) (msg (G_ "Updates cannot be checked on this system yet")))
                      (else ok-title)))
         (description
          (cond ((pair? warnings)
                 (msg (G_ "Open each one marked with a warning to see what to do about it.")))
                ((eq? verdict 'ok)
                 (msg (G_ "This means no signs of trouble were found, read from how this computer is set up.")))
                (else (msg (G_ "Some of it could not be read on this computer."))))))
    (if (null? entries)
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Updates could not be checked")))
                    (list 'description (msg (G_ "Nothing is known about how updates reach this computer.")))))
        (append
         (list (list 'report (list 'verdict verdict) (list 'title title)
                     (list 'description description)))
         (home-rows all sourceless-problems total ok-title)
         (section (G_ "Status now")
                  (G_ "What is waiting to be installed on this computer.")
                  now)
         (section (G_ "Keeps itself up to date")
                  (G_ "Whether this computer looks for updates and installs them by itself.")
                  setup)
         (section (G_ "Where updates come from")
                  (G_ "Security updates should come straight from the distribution, and every installed package from a software source.")
                  (append source sourceless systems))
         (section (G_ "Package files")
                  (G_ "Every file a package installed, compared with the checksum it came with. Your own settings in /etc are not counted.")
                  files)
         (integrity-notes entries)))))

