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
;;                      (shared-end (folders N) (services N) (more 0|1) (usershares 0|1))))
;;
;; state: 0 none set up, 1 set, 2 switched off, 3 could not be read.
;; entries: counted up to 1000, -1 could not be read. kind: "samba" (a share
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
    (cond ((< n 0) (msg (G_ "could not be looked in")))
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

(define (report input)
  (let* ((entries (numbered (section-of input 'collection)))
         (config (first-with 'shared-config entries))
         (end (first-with 'shared-end entries))
         (folders (keep (lambda (e) (eq? (car (cdr e)) 'shared-folder)) entries))
         (others (keep (lambda (e) (= (field (cdr e) 'standard) 0)) folders))
         (services (map cdr (keep (lambda (e) (eq? (car (cdr e)) 'shared-service)) entries)))
         (n-others (length others))
         (n-services (length services)))
    (if (or (not config) (not end))
        (list (list 'report (list 'verdict 'unknown)
                    (list 'title (msg (G_ "Your folders could not be looked at")))
                    (list 'description (msg (G_ "Nothing is known about the shared folder.")))))
        (append
         (list (list 'report
                     (list 'verdict (cond ((> n-services 0) 'warning)
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
         (if (= (field end 'usershares) 1)
             (list (list 'note (msg (G_ "Folders shared from the file manager could not be read: your account may not read where Samba keeps them."))))
             '())
         (if (= (field end 'more) 1)
             (list (list 'note (msg (G_ "There were more than could be listed."))))
             '())))))
