;; SPDX-License-Identifier: GPL-3.0-only
;; Shared Folder: the report on the collection ("gaudit-orchestrator shared").
;;
;; Evaluated by gaudit-engine in (ice-9 sandbox): pure bindings only, no I/O.
;; The input is data, never code:
;;
;;   (input (system (host "...") (distro "...") (backend "..."))
;;          (level "quick"|"full")
;;          (collection (shared-config (state S) (standard "...") (exists 0|1) (locale "...")
;;                                     (default "...") (names N))
;;                      (shared-folder (name "...") (lang "...") (machine 0|1) (current 0|1)
;;                                     (standard 0|1) (link 0|1) (target "...") (case 0|1)
;;                                     (entries N)) ...
;;                      (shared-service (kind "...") (name "...") (path "...")) ...
;;                      (shared-secret (path "...") (reason "...") (by "...")) ...
;;                      (shared-secret-scan (folders N) (skipped N) (found N) (more 0|1)
;;                                          (truncated 0|1))
;;                      (shared-end (folders N) (services N) (more 0|1) (usershares 0|1))))
;;
;; state: 0 none set up, 1 set, 2 switched off, 3 could not be read.
;; entries: counted up to 1000, -1 could not be read, -2 on another
;; filesystem than the home folder (a mount), not looked in, since listing
;; it may fetch it over the network. kind: "samba" (a share
;; in smb.conf), "samba-user" (made from the file manager), "gnome" (GNOME
;; Sharing, running).
;;
;; The good practice behind it: what is shared on the local network is
;; gathered in one place, the shared folder. A folder that looks like it is
;; a recommendation, never a warning, since it may be kept on purpose; a
;; service that shares folders is a warning, since people often do not
;; know it runs. Texts are English msgids in the plugin's own text domain
;; (G_, and N_ for a singular and plural pair), with {key} placeholders.

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

(define (keep pred lst)
  (cond ((null? lst) '())
        ((pred (car lst)) (cons (car lst) (keep pred (cdr lst))))
        (else (keep pred (cdr lst)))))

(define (first-with head entries)
  (cond ((null? entries) #f)
        ((eq? (car (cdar entries)) head) (cdar entries))
        (else (first-with head (cdr entries)))))

(define (msg text . args) (cons 'msg (cons text args)))
(define (msgn forms n . args) (cons 'msgn (append forms (cons n args))))

;; --- Languages -----------------------------------------------------------

;; The languages people here are most likely to have had; others are shown
;; by their code.
(define languages
  (list (cons "" (G_ "English"))
        (cons "nb" (G_ "Norwegian Bokmål"))
        (cons "nn" (G_ "Norwegian Nynorsk"))
        (cons "da" (G_ "Danish"))
        (cons "sv" (G_ "Swedish"))
        (cons "fi" (G_ "Finnish"))
        (cons "is" (G_ "Icelandic"))
        (cons "de" (G_ "German"))
        (cons "nl" (G_ "Dutch"))
        (cons "fr" (G_ "French"))
        (cons "es" (G_ "Spanish"))
        (cons "it" (G_ "Italian"))
        (cons "pt" (G_ "Portuguese"))
        (cons "pl" (G_ "Polish"))
        (cons "uk" (G_ "Ukrainian"))
        (cons "ru" (G_ "Russian"))))

;; "nb_NO" and "nb" alike.
(define (base-lang code)
  (let loop ((i 0))
    (cond ((= i (string-length code)) code)
          ((memv (string-ref code i) '(#\_ #\@ #\.)) (substring code 0 i))
          (else (loop (+ i 1))))))

(define (language code)
  (let ((entry (assoc (base-lang code) languages)))
    (if entry (msg (cdr entry)) (list 'text code))))

;; --- The report ------------------------------------------------------------

(define (row verdict title subtitle . more)
  (append (list 'row (list 'verdict verdict) (list 'title title) (list 'subtitle subtitle)) more))

(define (in-home name) (list 'text (string-append "~/" name)))

(define (config-row c)
  (let ((standard (field c 'standard)))
    (case (field c 'state)
      ((1) (if (= (field c 'exists) 1)
               (row 'ok (list 'text standard)
                    (msg (G_ "The folder for sharing, set in your user folder settings")))
               (row 'advice (list 'text standard)
                    (msg (G_ "Set as the folder for sharing, but it is not there")))))
      ((2) (row 'ok (msg (G_ "The folder for sharing is switched off"))
                (msg (G_ "Your user folder settings point it at the home folder itself"))))
      ((0) (row 'advice (msg (G_ "No folder for sharing is set up"))
                (msg (G_ "Programs that share then choose a folder of their own"))))
      (else (row 'unknown (msg (G_ "Your user folder settings could not be read"))
                 (msg (G_ "They are not written the way the system writes them")))))))

(define (contents f)
  (let ((n (field f 'entries)))
    (cond ((= n -2) (msg (G_ "on another disk or a network folder, not looked in")))
          ((< n 0) (msg (G_ "could not be looked in")))
          ((= n 0) (msg (G_ "empty")))
          ((>= n 1000) (msg (G_ "1000 items or more")))
          (else (msgn (N_ "{n} item" "{n} items") n (list 'n n))))))

(define (folder-subtitle f)
  (let ((lang (list 'lang (language (field f 'lang)))))
    (cond ((= (field f 'link) 1)
           (msg (G_ "A link to {target}") (list 'target (field f 'target))))
          ((= (field f 'case) 1)
           (msg (G_ "The {lang} name in other letters · {contents}") lang
                (list 'contents (contents f))))
          ((= (field f 'current) 0)
           (msg (G_ "An older {lang} name · {contents}") lang (list 'contents (contents f))))
          (else (msg (G_ "The {lang} name · {contents}") lang (list 'contents (contents f)))))))

(define (folder-row entry)
  (let ((n (car entry)) (f (cdr entry)))
    (row 'advice (in-home (field f 'name)) (folder-subtitle f)
         (list 'fix 'tidy (list 'item n)))))

(define (service-subtitle s)
  (let ((name (list 'name (field s 'name)))
        (kind (field s 'kind)))
    (cond ((equal? kind "samba-user") (msg (G_ "Shared from the file manager (Samba) as {name}") name))
          ((equal? kind "gnome") (msg (G_ "Shared by GNOME Sharing, which is running")))
          (else (msg (G_ "Shared by Samba as {name}") name)))))

(define (service-row s)
  (row 'warning (list 'text (field s 'path)) (service-subtitle s)))

(define (home verdict title subtitle)
  (list 'home (list 'verdict verdict) (list 'title title) (list 'subtitle subtitle)))

;; --- Secrets in folders for sharing (John, 2026-11-19) ------------------------
;;
;; A file that looks like a secret, put by mistake in the folder for
;; sharing, a folder that looks like it, or a folder a service shares.
;; Where a service shares it, others on the local network may fetch it: a
;; warning. In a folder for sharing that nothing shares now, a
;; recommendation: it is the place for what is to be shared, and a service
;; switched on later would share it.

(define secret-kinds
  (list (cons "openssh-private-key" (G_ "SSH private key"))
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

(define (secret-kind id)
  (let ((entry (assoc id secret-kinds)))
    (if entry (msg (cdr entry)) (msg (G_ "Looks like a secret")))))

(define (shared-by by)
  (cond ((equal? by "gnome") (msg (G_ "GNOME Sharing shares it on the local network")))
        ((equal? by "samba-user") (msg (G_ "shared on the local network from the file manager (Samba)")))
        (else (msg (G_ "Samba shares it on the local network")))))

(define (secret-row entry)
  (let* ((n (car entry)) (f (cdr entry)) (shared (not (equal? (field f 'by) ""))))
    (row (if shared 'warning 'advice) (list 'text (field f 'path))
         (msg (G_ "{kind} · {why}") (list 'kind (secret-kind (field f 'reason)))
              (list 'why (if shared
                             (shared-by (field f 'by))
                             (msg (G_ "in a folder for sharing, which nothing shares now")))))
         (list 'fix (if shared 'secret-shared 'secret-public) (list 'item n)))))

(define (report input)
  (let* ((entries (numbered (section-of input 'collection)))
         (config (first-with 'shared-config entries))
         (end (first-with 'shared-end entries))
         (folders (keep (lambda (e) (eq? (car (cdr e)) 'shared-folder)) entries))
         (others (keep (lambda (e) (= (field (cdr e) 'standard) 0)) folders))
         (services (map cdr (keep (lambda (e) (eq? (car (cdr e)) 'shared-service)) entries)))
         (n-others (length others))
         (n-services (length services))
         (level (let ((l (assq 'level (cdr input)))) (if l (cadr l) "quick")))
         (secrets (keep (lambda (e) (eq? (car (cdr e)) 'shared-secret)) entries))
         (scan (first-with 'shared-secret-scan entries))
         (n-shared-secrets (length (keep (lambda (e) (not (equal? (field (cdr e) 'by) ""))) secrets))))
    (if (or (not config) (not end))
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Your folders could not be looked at")))
                    (list 'description (msg (G_ "Nothing is known about the shared folder.")))))
        (append
         (list (list 'report
                     (list 'verdict (cond ((> (+ n-services n-shared-secrets) 0) 'warning)
                                          ((= (field config 'state) 3) 'unknown)
                                          (else 'ok)))
                     (list 'title
                           (cond ((> n-services 0)
                                  (msgn (N_ "{n} folder is shared on the local network"
                                            "{n} folders are shared on the local network")
                                        n-services (list 'n n-services)))
                                 ((> n-others 0)
                                  (msgn (N_ "{n} more folder looks like the shared folder"
                                            "{n} more folders look like the shared folder")
                                        n-others (list 'n n-others)))
                                 (else (msg (G_ "There is one folder for sharing")))))
                     (list 'description
                           (msg (G_ "What is shared is best kept in one folder, so it is clear what others on the network can read. A folder that looks like the shared folder is a recommendation: it may be kept on purpose.")))))
         ;; Home: what is shared, which people often do not know; the
         ;; duplicates are recommendations and stay off Home.
         (if (> n-shared-secrets 0)
             (list (home 'warning
                         (msgn (N_ "{n} secret is in a folder shared on the local network"
                                   "{n} secrets are in folders shared on the local network")
                               n-shared-secrets (list 'n n-shared-secrets))
                         (msg (G_ "Move them into a folder of your own"))))
             '())
         (if (> n-services 0)
             (list (home 'warning
                         (msgn (N_ "{n} folder is shared on the local network"
                                   "{n} folders are shared on the local network")
                               n-services (list 'n n-services))
                         (msg (G_ "Check that the sharing is meant"))))
             (list (home (if (= (field config 'state) 3) 'unknown 'ok)
                         (if (= (field config 'state) 1)
                             (msg (G_ "{folder} is the folder for sharing")
                                  (list 'folder (field config 'standard)))
                             (msg (G_ "No folder is shared")))
                         (msg (G_ "Nothing needs attention")))))
         (list (list 'section (list 'title (msg (G_ "The Folder for Sharing")))
                     (list 'description (msg (G_ "The one your desktop uses for what you share with others on the local network.")))))
         (list (config-row config))
         (if (> n-others 0)
             (cons (list 'section (list 'title (msg (G_ "Folders That Look Like It")))
                         (list 'description (msg (G_ "Their names are ones the folder for sharing has had, in another language or an older version. Two such folders make it unclear which one is shared."))))
                   (map folder-row others))
             '())
         (if (> n-services 0)
             (cons (list 'section (list 'title (msg (G_ "Shared on the Local Network")))
                         (list 'description (msg (G_ "Others on the same network can read what is in these folders, at home or on a café's Wi-Fi."))))
                   (map service-row services))
             '())
         (if scan
             (cons (list 'section (list 'title (msg (G_ "Secrets in Folders for Sharing")))
                         (list 'description (msg (G_ "Files that look like secrets, such as keys and stored logins, put in a folder for sharing, often by mistake. What a service shares, others on the local network can fetch."))))
                   (if (null? secrets)
                       (list (row 'ok (msg (G_ "No secrets found in the folders for sharing"))
                                  (msgn (N_ "{n} folder searched" "{n} folders searched")
                                        (field scan 'folders) (list 'n (field scan 'folders)))))
                       (map secret-row secrets)))
             '())
         (if (and scan (> (field scan 'skipped) 0))
             (list (list 'note (msgn (N_ "{n} folder was not searched: it is on another disk or a network folder, or a link, and looking in it may fetch it over the network."
                                         "{n} folders were not searched: they are on another disk or a network folder, or links, and looking in them may fetch them over the network.")
                                     (field scan 'skipped) (list 'n (field scan 'skipped)))))
             '())
         (if (and scan (equal? level "quick") (> n-services 0))
             (list (list 'note (msg (G_ "Other folders a service shares are searched for secrets in the full report, and on Home at the Thorough level."))))
             '())
         (if (and scan (= (field scan 'truncated) 1))
             (list (list 'note (msg (G_ "The search for secrets stopped at its limit in a large folder, so not every file was looked at."))))
             '())
         (if (and scan (= (field scan 'more) 1))
             (list (list 'note (msg (G_ "Only the first secrets found are listed; there are more."))))
             '())
         (if (= (field end 'usershares) 1)
             (list (list 'note (msg (G_ "Folders shared from the file manager could not be read: your account may not read where Samba keeps them."))))
             '())
         (if (= (field end 'more) 1)
             (list (list 'note (msg (G_ "There were more than could be listed."))))
             '())))))
