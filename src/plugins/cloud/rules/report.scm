;; SPDX-License-Identifier: GPL-3.0-only
;; Cloud Services: the report on the collection ("gaudit-orchestrator cloud").
;;
;; Evaluated by gaudit-engine in (ice-9 sandbox): pure bindings only, no I/O.
;; The input is data, never code:
;;
;;   (input (system (host "...") (distro "...") (backend "..."))
;;          (level "quick"|"full")
;;          (collection (cloud-folder (client "...") (service "...") (how N) (path "...")
;;                                    (name "...") (encrypted 0|1) (gathered 0|1)) ...
;;                      (cloud-end (count N) (more 0|1) (gathering "...") (gatherings N)
;;                                 (rclone-unreadable 0|1))))
;;
;; how: 0 the client's settings name the folder, 1 its default folder is
;; there, 2 installed only, 3 mounted, 4 set up without a folder of its own.
;;
;; The good practice (AGENTS.md, the cloud plugin): files encrypted before
;; they leave (zero-knowledge), a jurisdiction with strong privacy, open
;; source, and a client the system keeps up to date. A service where the
;; provider can read the files is a warning (John, 2026-11-19), and so is a
;; client whose login is made by, or kept at, a web service of its own, or
;; not documented: that service can reach every file. A client the system
;; does not keep up to date (an AppImage) is a recommendation. Only properties that can be checked are said,
;; never lawsuits or reputation. Texts are English msgids in the plugin's
;; own text domain, with {key} placeholders.

;; --- What is known of each service and client (checked 2026-11-19) -----
;;
;; Sources: Dropbox's help on encrypted team folders (Business Plus,
;; Advanced, Enterprise only); Google Workspace's client-side encryption
;; (some Workspace editions only, not personal accounts); OneDrive's
;; Personal Vault (a second login, Microsoft holds the keys); MEGA's
;; licence (MEGA Limited Code Review Licence: for review only; the SDK is
;; BSD); pCloud's Crypto folder (paid); Tresorit (zero-knowledge, Swiss
;; Post); Nextcloud's end-to-end encryption (per folder, optional); ownCloud
;; (none of its own found); Jottacloud (its encryption not confirmed);
;; abraunegg/onedrive and rclone (the login made on the machine, the token
;; kept there); Insync (how its login is made is not documented).

(define services
  ;; id         name               encryption  where the provider is
  (list (list "dropbox"      "Dropbox"      'no       'usa)
        (list "nextcloud"    "Nextcloud"    'optional 'server)
        (list "owncloud"     "ownCloud"     'no       'server)
        (list "mega"         "MEGA"         'yes      'nz)
        (list "pcloud"       "pCloud"       'paid     'switzerland)
        (list "tresorit"     "Tresorit"     'yes      'switzerland)
        (list "onedrive"     "OneDrive"     'no       'usa)
        (list "google-drive" "Google Drive" 'no       'usa)
        (list "jottacloud"   "Jottacloud"   'unknown  'norway)
        (list "proton-drive" "Proton Drive" 'yes      'switzerland)
        (list "webdav"       "WebDAV"       'unknown  'server)))

(define clients
  ;; id          name                  its own  source    upkeep     login
  (list (list "dropbox"   "Dropbox"            #t 'closed  'unknown  'local)
        (list "nextcloud" "Nextcloud"          #t 'open    'unknown  'local)
        (list "owncloud"  "ownCloud"           #t 'open    'unknown  'local)
        (list "megasync"  "MEGAsync"           #t 'review  'unknown  'local)
        (list "pcloud"    "pCloud"             #t 'closed  'appimage 'local)
        (list "tresorit"  "Tresorit"           #t 'closed  'unknown  'local)
        (list "onedrive"  "the onedrive client" #f 'open   'unknown  'local)
        (list "insync"    "Insync"             #f 'closed  'unknown  'undocumented)
        (list "jotta-cli" "jotta-cli"          #t 'unknown 'unknown  'local)
        (list "rclone"    "rclone"             #f 'open    'unknown  'local)))

;; --- Reading the input ---------------------------------------------------

(define (field item key)
  (let ((entry (assq key (cdr item))))
    (and entry (cadr entry))))

(define (section-of input key)
  (let ((entry (assq key (cdr input))))
    (if entry (cdr entry) '())))

(define (keep pred lst)
  (cond ((null? lst) '())
        ((pred (car lst)) (cons (car lst) (keep pred (cdr lst))))
        (else (keep pred (cdr lst)))))

(define (first-with head items)
  (cond ((null? items) #f)
        ((eq? (car (car items)) head) (car items))
        (else (first-with head (cdr items)))))

(define (msg text . args) (cons 'msg (cons text args)))
(define (msgn forms n . args) (cons 'msgn (append forms (cons n args))))

(define (service-of id) (or (assoc id services) (list id id 'unknown 'unknown)))
(define (client-of id) (or (assoc id clients) (list id id #t 'unknown 'unknown 'undocumented)))

;; --- What each property is called ---------------------------------------------

(define (law-text where)
  (case where
    ((usa) (msg (G_ "under the law of the USA")))
    ((switzerland) (msg (G_ "under Swiss law")))
    ((norway) (msg (G_ "under Norwegian law")))
    ((nz) (msg (G_ "under the law of New Zealand")))
    (else (msg (G_ "under the law where its server is")))))

(define (encryption-text f kind)
  (cond ((= (field f 'encrypted) 1) (msg (G_ "encrypted before it leaves the computer")))
        ((eq? kind 'yes) (msg (G_ "encrypted before it leaves the computer")))
        ((eq? kind 'optional) (msg (G_ "the provider can read it unless a folder is set to be encrypted")))
        ((eq? kind 'paid) (msg (G_ "the provider can read it, except in a paid encrypted folder")))
        ((eq? kind 'no) (msg (G_ "the provider can read it")))
        (else (msg (G_ "whether the provider can read it is not known")))))

(define (where-text f)
  (let ((path (list 'path (field f 'path))))
    (case (field f 'how)
      ((0) (msg (G_ "{path}") path))
      ((1) (msg (G_ "probably {path}, its usual folder") path))
      ((3) (msg (G_ "mounted at {path}") path))
      ((4) (msg (G_ "set up as {name}, without a folder of its own") (list 'name (field f 'name))))
      (else (msg (G_ "installed; where its folder is cannot be seen"))))))

;; --- Judging one finding ------------------------------------------------------

(define (encrypted? f kind)
  (or (= (field f 'encrypted) 1) (eq? kind 'yes)))

(define (verdict-of f)
  (let* ((s (service-of (field f 'service)))
         (c (client-of (field f 'client)))
         (login (list-ref c 5))
         (upkeep (list-ref c 4)))
    (cond ((not (eq? login 'local)) 'warning)
          ((not (encrypted? f (list-ref s 2))) 'warning)
          ((eq? upkeep 'appimage) 'advice)
          (else 'ok))))

(define (title-of f)
  (let* ((s (service-of (field f 'service)))
         (c (client-of (field f 'client))))
    (if (list-ref c 2)
        (list 'text (list-ref s 1))
        (msg (G_ "{service} through {client}") (list 'service (list 'text (list-ref s 1)))
             (list 'client (list 'text (list-ref c 1)))))))

(define (subtitle-of f)
  (let* ((s (service-of (field f 'service)))
         (c (client-of (field f 'client)))
         (login (list-ref c 5)))
    (if (not (eq? login 'local))
        (msg (G_ "{where} · where its login is made, and who keeps it, is not documented")
             (list 'where (where-text f)))
        (msg (G_ "{where} · {encryption} · {law}")
             (list 'where (where-text f))
             (list 'encryption (encryption-text f (list-ref s 2)))
             (list 'law (law-text (list-ref s 3)))))))

(define (row-of f)
  (list 'row (list 'verdict (verdict-of f)) (list 'title (title-of f))
        (list 'subtitle (subtitle-of f))))

(define (home verdict title subtitle)
  (list 'home (list 'verdict verdict) (list 'title title) (list 'subtitle subtitle)))

;; --- The report -----------------------------------------------------------------

(define (report input)
  (let* ((items (section-of input 'collection))
         (found (keep (lambda (i) (eq? (car i) 'cloud-folder)) items))
         (end (first-with 'cloud-end items))
         (warned (keep (lambda (f) (eq? (verdict-of f) 'warning)) found))
         (login-warned (keep (lambda (f) (not (eq? (list-ref (client-of (field f 'client)) 5) 'local)))
                             found))
         (with-folder (keep (lambda (f) (and (not (equal? (field f 'path) ""))
                                             (memv (field f 'how) '(0 3))))
                            found))
         (scattered (keep (lambda (f) (= (field f 'gathered) 0)) with-folder))
         (n (length found))
         (nw (length warned)))
    (if (not end)
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Cloud services could not be looked for")))
                    (list 'description (msg (G_ "Nothing is known about the cloud services on this computer.")))))
        (append
         (list (list 'report
                     (list 'verdict (if (> nw 0) 'warning 'ok))
                     (list 'title
                           (cond ((> (length login-warned) 0)
                                  (msgn (N_ "{n} cloud program logs in in a way that is not documented"
                                            "{n} cloud programs log in in a way that is not documented")
                                        (length login-warned) (list 'n (length login-warned))))
                                 ((> nw 0)
                                  (msgn (N_ "{n} cloud service where the provider can read your files"
                                            "{n} cloud services where the provider can read your files")
                                        nw (list 'n nw)))
                                 ((= n 0) (msg (G_ "No cloud services found")))
                                 (else (msgn (N_ "{n} cloud service found" "{n} cloud services found")
                                             n (list 'n n)))))
                     (list 'description
                           (msg (G_ "What is in a cloud folder leaves the computer and is kept by someone else. Best is when it is encrypted before it leaves, so the provider cannot read it, under a law that protects privacy, with a program whose source code is open and that the system keeps up to date.")))))
         ;; Home: each warning, as a summary of why; recommendations stay
         ;; off Home.
         (if (> nw 0)
             (map (lambda (f)
                    (home 'warning (title-of f)
                          (if (eq? (list-ref (client-of (field f 'client)) 5) 'local)
                              (msg (G_ "The provider can read what is sent there"))
                              (msg (G_ "Where its login is made, and who keeps it, is not documented")))))
                  warned)
             (list (home 'ok
                         (if (= n 0)
                             (msg (G_ "No cloud services found"))
                             (msgn (N_ "{n} cloud service found" "{n} cloud services found")
                                   n (list 'n n)))
                         (msg (G_ "Nothing needs attention")))))
         (if (> n 0)
             (cons (list 'section (list 'title (msg (G_ "Cloud Services on This Computer")))
                         (list 'description (msg (G_ "Programs that keep a copy of your files in a cloud service, and what is known about each."))))
                   (map row-of found))
             '())
         ;; Gathering them: one place to see what leaves the computer.
         (if (or (> (length scattered) 0) (> (field end 'gatherings) 1))
             (list (list 'section (list 'title (msg (G_ "Where the Cloud Folders Are")))
                         (list 'description (msg (G_ "Cloud folders gathered under one folder, such as ~/Cloud, give one place to see what leaves the computer."))))
                   (if (> (field end 'gatherings) 1)
                       (list 'row (list 'verdict 'advice)
                             (list 'title (msgn (N_ "{n} folder for gathering cloud folders"
                                                    "{n} folders for gathering cloud folders")
                                                (field end 'gatherings) (list 'n (field end 'gatherings))))
                             (list 'subtitle (msg (G_ "One is enough; the others make it unclear where they belong"))))
                       (list 'row (list 'verdict 'advice)
                             (list 'title (msgn (N_ "{n} cloud folder is not gathered with the others"
                                                    "{n} cloud folders are not gathered with the others")
                                                (length scattered) (list 'n (length scattered))))
                             (list 'subtitle (msg (G_ "Move each in its own program's settings, never in the file manager"))))))
             '())
         (if (> (length with-folder) 0)
             (list (list 'note (msg (G_ "A cloud folder is moved in its own program's settings. Moved in the file manager, the program may take your files as deleted, and delete them from the service and every computer that syncs it."))))
             '())
         (if (= (field end 'rclone-unreadable) 1)
             (list (list 'note (msg (G_ "rclone's settings are encrypted, so its setups were not read."))))
             '())
         (if (= (field end 'more) 1)
             (list (list 'note (msg (G_ "There were more than could be listed."))))
             '())))))
