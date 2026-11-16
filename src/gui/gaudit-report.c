/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-report.h"
#include "gaudit-task-page.h"

/* --- A strict reader for one line --------------------------------------- */

#define MAX_DEPTH  8
#define MAX_NODES  256
#define MAX_TEXT   1024
#define MAX_LINES  512

typedef enum { SX_LIST, SX_STRING, SX_INT, SX_SYMBOL } SxKind;

typedef struct Sx {
    SxKind kind;
    char *text;        /* string or symbol */
    gint64 num;
    GPtrArray *items;  /* list: Sx* */
} Sx;

static void sx_free(gpointer p)
{
    Sx *sx = p;
    if (sx == NULL)
        return;
    g_free(sx->text);
    if (sx->items != NULL)
        g_ptr_array_unref(sx->items);
    g_free(sx);
}

typedef struct {
    const char *p;
    int nodes;
} Reader;

static Sx *read_sx(Reader *r, int depth);

static Sx *read_list(Reader *r, int depth)
{
    if (depth > MAX_DEPTH)
        return NULL;
    Sx *sx = g_new0(Sx, 1);
    sx->kind = SX_LIST;
    sx->items = g_ptr_array_new_with_free_func(sx_free);
    r->p++;  /* '(' */
    for (;;) {
        while (*r->p == ' ')
            r->p++;
        if (*r->p == ')') {
            r->p++;
            return sx;
        }
        Sx *item = read_sx(r, depth + 1);
        if (item == NULL) {
            sx_free(sx);
            return NULL;
        }
        g_ptr_array_add(sx->items, item);
    }
}

/* "..." with \" and \\ only; printable bytes (UTF-8 passes, checked after). */
static Sx *read_string(Reader *r)
{
    GString *s = g_string_new(NULL);
    r->p++;
    for (;;) {
        unsigned char c = (unsigned char)*r->p;
        if (c == '"')
            break;
        if (c == '\\') {
            char e = r->p[1];
            if (e != '"' && e != '\\')
                goto bad;
            g_string_append_c(s, e);
            r->p += 2;
        } else if (c < 0x20 || c == 0x7f) {
            goto bad;  /* also the end of the line */
        } else {
            g_string_append_c(s, (char)c);
            r->p++;
        }
        if (s->len > MAX_TEXT)
            goto bad;
    }
    r->p++;
    if (!g_utf8_validate(s->str, (gssize)s->len, NULL))
        goto bad;
    Sx *sx = g_new0(Sx, 1);
    sx->kind = SX_STRING;
    sx->text = g_string_free(s, FALSE);
    return sx;
bad:
    g_string_free(s, TRUE);
    return NULL;
}

static Sx *read_atom(Reader *r)
{
    const char *start = r->p;
    if (*r->p == '-' && g_ascii_isdigit(r->p[1]))
        r->p++;
    if (g_ascii_isdigit(*r->p)) {
        while (g_ascii_isdigit(*r->p))
            r->p++;
        if (r->p - start > 12 || (*r->p != ' ' && *r->p != ')'))
            return NULL;
        Sx *sx = g_new0(Sx, 1);
        sx->kind = SX_INT;
        sx->num = g_ascii_strtoll(start, NULL, 10);
        return sx;
    }
    while (g_ascii_islower(*r->p) || g_ascii_isdigit(*r->p) || *r->p == '-')
        r->p++;
    if (r->p == start || r->p - start > 64 || (*r->p != ' ' && *r->p != ')'))
        return NULL;
    Sx *sx = g_new0(Sx, 1);
    sx->kind = SX_SYMBOL;
    sx->text = g_strndup(start, (gsize)(r->p - start));
    return sx;
}

static Sx *read_sx(Reader *r, int depth)
{
    if (++r->nodes > MAX_NODES)
        return NULL;
    if (*r->p == '(')
        return read_list(r, depth);
    if (*r->p == '"')
        return read_string(r);
    return read_atom(r);
}

static Sx *parse_line(const char *line)
{
    if (line == NULL || line[0] != '(' || strlen(line) > 4 * MAX_TEXT)
        return NULL;
    Reader r = { .p = line };
    Sx *sx = read_sx(&r, 0);
    if (sx == NULL || *r.p != '\0') {
        sx_free(sx);
        return NULL;
    }
    return sx;
}

/* --- Checking the shape ------------------------------------------------- */

static Sx *item(const Sx *list, guint i)
{
    return i < list->items->len ? g_ptr_array_index(list->items, i) : NULL;
}

static gboolean is_symbol(const Sx *sx, const char *name)
{
    return sx != NULL && sx->kind == SX_SYMBOL && (name == NULL || strcmp(sx->text, name) == 0);
}

/* (name ...) */
static gboolean headed(const Sx *sx, const char *name)
{
    return sx != NULL && sx->kind == SX_LIST && sx->items->len > 0 && is_symbol(item(sx, 0), name);
}

static gboolean valid_msg(const Sx *sx, int depth);

/* (key VALUE) pairs from index first on. */
static gboolean valid_args(const Sx *sx, guint first, int depth)
{
    for (guint i = first; i < sx->items->len; i++) {
        const Sx *a = item(sx, i);
        if (a->kind != SX_LIST || a->items->len != 2 || !is_symbol(item(a, 0), NULL))
            return FALSE;
        const Sx *v = item(a, 1);
        if (v->kind != SX_STRING && v->kind != SX_INT && !valid_msg(v, depth + 1))
            return FALSE;
    }
    return TRUE;
}

static gboolean valid_msg(const Sx *sx, int depth)
{
    if (depth > 3 || sx == NULL || sx->kind != SX_LIST)
        return FALSE;
    if (headed(sx, "text"))
        return sx->items->len == 2 && item(sx, 1)->kind == SX_STRING;
    if (headed(sx, "msg"))
        return sx->items->len >= 2 && item(sx, 1)->kind == SX_STRING && valid_args(sx, 2, depth);
    if (headed(sx, "msgn"))
        return sx->items->len >= 4 && item(sx, 1)->kind == SX_STRING
               && item(sx, 2)->kind == SX_STRING && item(sx, 3)->kind == SX_INT
               && item(sx, 3)->num >= 0 && valid_args(sx, 4, depth);
    return FALSE;
}

/* The fields of (head (key value) ...): each key in keys exactly once (an
 * optional one may be missing), nothing else. Fills out[] by key. */
static gboolean fields(const Sx *sx, const char *const *keys, gboolean last_optional, Sx **out)
{
    guint n = g_strv_length((char **)keys);
    for (guint k = 0; k < n; k++)
        out[k] = NULL;
    for (guint i = 1; i < sx->items->len; i++) {
        const Sx *f = item(sx, i);
        if (f->kind != SX_LIST || f->items->len < 2 || !is_symbol(item(f, 0), NULL))
            return FALSE;
        guint k = 0;
        while (k < n && strcmp(keys[k], item(f, 0)->text) != 0)
            k++;
        if (k == n || out[k] != NULL)
            return FALSE;
        out[k] = (Sx *)f;
    }
    for (guint k = 0; k < n; k++)
        if (out[k] == NULL && !(last_optional && k == n - 1))
            return FALSE;
    return TRUE;
}

static gboolean verdict_of(const Sx *field, gaudit_verdict *out)
{
    if (field->items->len != 2 || !is_symbol(item(field, 1), NULL))
        return FALSE;
    const char *v = item(field, 1)->text;
    *out = strcmp(v, "ok") == 0 ? GAUDIT_VERDICT_OK
         : strcmp(v, "warning") == 0 ? GAUDIT_VERDICT_WARNING
         : strcmp(v, "critical") == 0 ? GAUDIT_VERDICT_CRITICAL
         : strcmp(v, "unknown") == 0 ? GAUDIT_VERDICT_UNKNOWN : (gaudit_verdict)-1;
    return (int)*out >= 0;
}

/* A row may also be advice: a recommendation, not a finding. It counts as
 * fine, so it never makes the verdict worse and never reaches Home. */
static gboolean is_advice(const Sx *field)
{
    return field != NULL && field->items->len == 2 && is_symbol(item(field, 1), NULL)
           && strcmp(item(field, 1)->text, "advice") == 0;
}

/* (key MSG) */
static gboolean msg_field(const Sx *field)
{
    return field->items->len == 2 && valid_msg(item(field, 1), 0);
}

struct _GauditReport {
    gaudit_verdict verdict;
    Sx *head;
    GPtrArray *elements;  /* Sx*: section, row, note */
};

void gaudit_report_free(GauditReport *report)
{
    if (report == NULL)
        return;
    sx_free(report->head);
    if (report->elements != NULL)
        g_ptr_array_unref(report->elements);
    g_free(report);
}

GauditReport *gaudit_report_parse(const char *const *lines, gsize n_lines)
{
    if (lines == NULL || n_lines == 0 || n_lines > MAX_LINES)
        return NULL;
    g_autoptr(GauditReport) r = g_new0(GauditReport, 1);
    r->elements = g_ptr_array_new_with_free_func(sx_free);
    for (gsize i = 0; i < n_lines; i++) {
        Sx *sx = parse_line(lines[i]);
        if (sx == NULL)
            return NULL;
        Sx *f[4];
        gboolean ok = FALSE;
        if (i == 0) {
            static const char *const keys[] = { "verdict", "title", "description", NULL };
            ok = headed(sx, "report") && fields(sx, keys, FALSE, f) && verdict_of(f[0], &r->verdict)
                 && msg_field(f[1]) && msg_field(f[2]);
            if (ok)
                r->head = sx;
        } else if (headed(sx, "section")) {
            static const char *const keys[] = { "title", "description", NULL };
            ok = fields(sx, keys, FALSE, f) && msg_field(f[0]) && msg_field(f[1]);
        } else if (headed(sx, "row")) {
            static const char *const keys[] = { "verdict", "title", "subtitle", "fix", NULL };
            gaudit_verdict v;
            ok = fields(sx, keys, TRUE, f) && (verdict_of(f[0], &v) || is_advice(f[0]))
                 && msg_field(f[1]) && msg_field(f[2]);
            /* (fix ID (item N)) */
            if (ok && f[3] != NULL) {
                const Sx *at = item(f[3], 2);
                ok = f[3]->items->len == 3 && is_symbol(item(f[3], 1), NULL) && headed(at, "item")
                     && at->items->len == 2 && item(at, 1)->kind == SX_INT
                     && item(at, 1)->num >= 0 && item(at, 1)->num < 100000;
            }
        } else if (headed(sx, "note")) {
            ok = sx->items->len == 2 && valid_msg(item(sx, 1), 0);
        } else if (headed(sx, "home")) {
            static const char *const keys[] = { "verdict", "title", "subtitle", NULL };
            gaudit_verdict v;
            ok = fields(sx, keys, FALSE, f) && verdict_of(f[0], &v) && msg_field(f[1])
                 && msg_field(f[2]);
        }
        if (!ok) {
            sx_free(sx);
            return NULL;
        }
        if (i > 0)
            g_ptr_array_add(r->elements, sx);
    }
    return g_steal_pointer(&r);
}

gaudit_verdict gaudit_report_verdict(const GauditReport *report)
{
    return report != NULL ? report->verdict : GAUDIT_VERDICT_UNKNOWN;
}

/* --- Texts ------------------------------------------------------------- */

static char *msg_text(const Sx *msg, const char *domain);

/* The value of {key} in msg's arguments, from index first on; NULL if none. */
static char *arg_text(const Sx *msg, guint first, const char *key, gsize key_len, const char *domain)
{
    for (guint i = first; i < msg->items->len; i++) {
        const Sx *a = item(msg, i);
        const char *name = item(a, 0)->text;
        if (strlen(name) != key_len || strncmp(name, key, key_len) != 0)
            continue;
        const Sx *v = item(a, 1);
        if (v->kind == SX_STRING)
            return g_strdup(v->text);
        if (v->kind == SX_INT)
            return g_strdup_printf("%" G_GINT64_FORMAT, v->num);
        return msg_text(v, domain);
    }
    return NULL;
}

/* The translated text with its {key} placeholders filled in; an unknown
 * placeholder stays as it is. Plain text throughout. */
static char *msg_text(const Sx *msg, const char *domain)
{
    const char *kind = item(msg, 0)->text;
    if (strcmp(kind, "text") == 0)
        return g_strdup(item(msg, 1)->text);
    const char *text;
    guint first;
    if (strcmp(kind, "msgn") == 0) {
        gint64 n = item(msg, 3)->num;
        text = g_dngettext(domain, item(msg, 1)->text, item(msg, 2)->text, (gulong)n);
        first = 4;
    } else {
        text = g_dgettext(domain, item(msg, 1)->text);
        first = 2;
    }
    GString *out = g_string_new(NULL);
    for (const char *p = text; *p != '\0';) {
        const char *open = strchr(p, '{');
        const char *close = open != NULL ? strchr(open, '}') : NULL;
        if (open == NULL || close == NULL) {
            g_string_append(out, p);
            break;
        }
        g_string_append_len(out, p, open - p);
        g_autofree char *value = arg_text(msg, first, open + 1, (gsize)(close - open - 1), domain);
        if (value != NULL)
            g_string_append(out, value);
        else
            g_string_append_len(out, open, close - open + 1);
        p = close + 1;
    }
    return g_string_free(out, FALSE);
}

/* The MSG of field key in element sx. */
static char *field_text(const Sx *sx, const char *key, const char *domain)
{
    for (guint i = 1; i < sx->items->len; i++) {
        const Sx *f = item(sx, i);
        if (strcmp(item(f, 0)->text, key) == 0)
            return msg_text(item(f, 1), domain);
    }
    return NULL;
}

static const Sx *field(const Sx *sx, const char *key)
{
    for (guint i = 1; i < sx->items->len; i++) {
        const Sx *f = item(sx, i);
        if (strcmp(item(f, 0)->text, key) == 0)
            return f;
    }
    return NULL;
}

char *gaudit_report_title(const GauditReport *report, const char *domain)
{
    return field_text(report->head, "title", domain);
}

static void home_row_free(gpointer p)
{
    GauditHomeRow *r = p;
    g_free(r->title);
    g_free(r->subtitle);
    g_free(r);
}

GPtrArray *gaudit_report_home_rows(const GauditReport *report, const char *domain)
{
    GPtrArray *rows = g_ptr_array_new_with_free_func(home_row_free);
    if (report == NULL)
        return rows;
    for (guint i = 0; i < report->elements->len; i++) {
        const Sx *e = g_ptr_array_index(report->elements, i);
        if (!headed(e, "home"))
            continue;
        GauditHomeRow *r = g_new0(GauditHomeRow, 1);
        r->verdict = GAUDIT_VERDICT_UNKNOWN;
        verdict_of(field(e, "verdict"), &r->verdict);
        r->title = field_text(e, "title", domain);
        r->subtitle = field_text(e, "subtitle", domain);
        g_ptr_array_add(rows, r);
    }
    if (rows->len == 0) {
        /* A rule that gives none: the report's own verdict and title. */
        GauditHomeRow *r = g_new0(GauditHomeRow, 1);
        r->verdict = report->verdict;
        r->title = field_text(report->head, "title", domain);
        r->subtitle = g_strdup("");
        g_ptr_array_add(rows, r);
    }
    return rows;
}

/* --- Showing it --------------------------------------------------------- */

typedef struct {
    GauditReportFixFn fn;
    gpointer data;
    GDestroyNotify free;
    int refs;
} FixCtx;

static void fix_ctx_unref(gpointer p)
{
    FixCtx *c = p;
    if (--c->refs > 0)
        return;
    if (c->free != NULL)
        c->free(c->data);
    g_free(c);
}

static void on_row_activated(AdwActionRow *row, gpointer user_data)
{
    FixCtx *c = user_data;
    const char *fix_id = g_object_get_data(G_OBJECT(row), "gaudit-fix");
    guint at = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(row), "gaudit-item"));
    GtkWidget *nav = gtk_widget_get_ancestor(GTK_WIDGET(row), ADW_TYPE_NAVIGATION_VIEW);
    AdwNavigationPage *page = fix_id != NULL && nav != NULL ? c->fn(fix_id, at, c->data) : NULL;
    if (page != NULL)
        adw_navigation_view_push(ADW_NAVIGATION_VIEW(nav), page);
}

static GtkWidget *small_note(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_add_css_class(label, "dim-label");
    gtk_widget_add_css_class(label, "caption");
    return label;
}

void gaudit_report_show(AdwStatusPage *status, const GauditReport *report, const char *domain,
                        GauditReportFixFn fix_fn, gpointer fix_data, GDestroyNotify fix_data_free)
{
    const char *icon = report->verdict == GAUDIT_VERDICT_OK ? "gaudit-status-high-symbolic"
                     : report->verdict == GAUDIT_VERDICT_WARNING ? "gaudit-status-medium-symbolic"
                     : report->verdict == GAUDIT_VERDICT_CRITICAL ? "gaudit-status-low-symbolic"
                     : "gaudit-status-unknown-symbolic";
    g_autofree char *title = field_text(report->head, "title", domain);
    g_autofree char *description = field_text(report->head, "description", domain);
    adw_status_page_set_paintable(status, NULL);
    adw_status_page_set_icon_name(status, icon);
    adw_status_page_set_title(status, title);
    adw_status_page_set_description(status, description);

    FixCtx *ctx = g_new0(FixCtx, 1);
    ctx->fn = fix_fn;
    ctx->data = fix_data;
    ctx->free = fix_data_free;
    ctx->refs = 1;

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    AdwPreferencesGroup *group = NULL;
    for (guint i = 0; i < report->elements->len; i++) {
        const Sx *e = g_ptr_array_index(report->elements, i);
        if (headed(e, "section")) {
            group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
            g_autofree char *t = field_text(e, "title", domain);
            g_autofree char *d = field_text(e, "description", domain);
            adw_preferences_group_set_title(group, t);
            adw_preferences_group_set_description(group, d);
            gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
        } else if (headed(e, "row")) {
            if (group == NULL) {
                group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
                gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
            }
            gaudit_verdict v = GAUDIT_VERDICT_UNKNOWN;
            gboolean advice = is_advice(field(e, "verdict"));
            if (!advice)
                verdict_of(field(e, "verdict"), &v);
            g_autofree char *t = field_text(e, "title", domain);
            g_autofree char *st = field_text(e, "subtitle", domain);
            AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
            /* Report texts and data from the system: plain text only. */
            adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
            adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), t);
            adw_action_row_set_subtitle(row, st);
            if (advice) {
                /* gAudit's own name: the meaning matters, so no theme replaces it. */
                GtkWidget *image = gtk_image_new_from_icon_name("gaudit-information-symbolic");
                gtk_widget_add_css_class(image, "accent");
                gtk_widget_set_tooltip_text(image, _("Recommendation"));
                gtk_accessible_update_property(GTK_ACCESSIBLE(image), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                               _("Recommendation"), -1);
                adw_action_row_add_prefix(row, image);
            } else {
                adw_action_row_add_prefix(row, gaudit_verdict_icon_new(v));
            }
            const Sx *fix = field(e, "fix");
            if (fix != NULL && fix_fn != NULL) {
                g_object_set_data_full(G_OBJECT(row), "gaudit-fix", g_strdup(item(fix, 1)->text), g_free);
                g_object_set_data(G_OBJECT(row), "gaudit-item",
                                  GUINT_TO_POINTER((guint)item(item(fix, 2), 1)->num));
                adw_action_row_add_suffix(row, gtk_image_new_from_icon_name("go-next-symbolic"));
                gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
                ctx->refs++;
                g_signal_connect_data(row, "activated", G_CALLBACK(on_row_activated), ctx,
                                      (GClosureNotify)(void (*)(void))fix_ctx_unref, 0);
            } else {
                adw_preferences_row_set_title_selectable(ADW_PREFERENCES_ROW(row), TRUE);
            }
            adw_preferences_group_add(group, GTK_WIDGET(row));
        } else if (headed(e, "note")) {
            g_autofree char *t = msg_text(item(e, 1), domain);
            gtk_box_append(GTK_BOX(box), small_note(t));
            group = NULL;
        }
    }
    fix_ctx_unref(ctx);
    if (gtk_widget_get_first_child(box) == NULL) {
        g_object_ref_sink(box);
        g_object_unref(box);
        return;
    }
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(status, clamp);
}
