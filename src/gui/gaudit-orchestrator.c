/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <gio/gio.h>
#include <string.h>

#include "gaudit-orchestrator.h"

#define MAX_OUTPUT (64 * 1024)
#define MAX_LINE   1024
#define READ_CHUNK 8192

struct _GauditOrchestrator {
    GSubprocess *proc;
    GCancellable *cancel;  /* stops reading at the timeout */
    GByteArray *pending;   /* bytes after the last complete line */
    gsize total;
    guint timeout_id;
    gboolean broken;
    GauditOrchestratorLineFn on_line;
    GauditOrchestratorDoneFn on_done;
    gpointer user_data;
};

typedef GauditOrchestrator Run;

static void finish(Run *run)
{
    if (run->timeout_id != 0)
        g_source_remove(run->timeout_id);
    run->on_done(run->broken, run->user_data);
    g_clear_object(&run->proc);
    g_clear_object(&run->cancel);
    g_byte_array_unref(run->pending);
    g_application_release(g_application_get_default());
    g_free(run);
}

static gboolean on_timeout(gpointer user_data)
{
    Run *run = user_data;
    run->timeout_id = 0;
    g_cancellable_cancel(run->cancel);  /* the read ends; finish follows */
    g_subprocess_force_exit(run->proc);
    return G_SOURCE_REMOVE;
}

static void on_exited(GObject *source, GAsyncResult *res, gpointer user_data)
{
    Run *run = user_data;
    g_autoptr(GError) error = NULL;
    if (!g_subprocess_wait_check_finish(G_SUBPROCESS(source), res, &error))
        g_debug("gaudit: orchestrator: %s", error->message);
    if (run->pending->len > 0)
        run->broken = TRUE;  /* output ended in the middle of a line */
    finish(run);
}

/* Hands every complete line in pending to on_line; FALSE on a violation. */
static gboolean take_lines(Run *run)
{
    for (;;) {
        const guint8 *data = run->pending->data;
        const guint8 *nl = memchr(data, '\n', run->pending->len);
        if (nl == NULL)
            return run->pending->len < MAX_LINE;
        gsize len = (gsize)(nl - data);
        if (len >= MAX_LINE || memchr(data, '\0', len) != NULL)
            return FALSE;
        char line[MAX_LINE];
        memcpy(line, data, len);
        line[len] = '\0';
        g_byte_array_remove_range(run->pending, 0, (guint)len + 1);
        if (!run->on_line(line, run->user_data))
            return FALSE;
    }
}

static void on_read(GObject *source, GAsyncResult *res, gpointer user_data)
{
    Run *run = user_data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(source), res, &error);

    gsize n = bytes != NULL ? g_bytes_get_size(bytes) : 0;
    if (n > 0) {
        run->total += n;
        g_byte_array_append(run->pending, g_bytes_get_data(bytes, NULL), (guint)n);
        if (run->total > MAX_OUTPUT || !take_lines(run)) {
            run->broken = TRUE;
            g_subprocess_force_exit(run->proc);
        }
    }
    if (n > 0 && !run->broken) {
        g_input_stream_read_bytes_async(G_INPUT_STREAM(source), READ_CHUNK, G_PRIORITY_DEFAULT,
                                        run->cancel, on_read, run);
        return;
    }
    /* End of output (or failure): wait for the process to exit. */
    g_subprocess_wait_check_async(run->proc, NULL, on_exited, run);
}

GauditOrchestrator *gaudit_orchestrator_start(const char *const *args, guint timeout_s,
                                              gboolean interactive,
                                              GauditOrchestratorLineFn on_line,
                                              GauditOrchestratorDoneFn on_done, gpointer user_data)
{
    Run *run = g_new0(Run, 1);
    run->on_line = on_line;
    run->on_done = on_done;
    run->user_data = user_data;
    run->pending = g_byte_array_new();
    run->cancel = g_cancellable_new();
    g_application_hold(g_application_get_default());  /* do not quit halfway */

    g_autoptr(GPtrArray) argv = g_ptr_array_new();
    g_ptr_array_add(argv, (gpointer)GAUDIT_ORCHESTRATOR_PATH);
    for (const char *const *a = args; a != NULL && *a != NULL; a++)
        g_ptr_array_add(argv, (gpointer)*a);
    g_ptr_array_add(argv, NULL);

    /* Nothing from our environment is passed on, except HOME. */
    g_autoptr(GSubprocessLauncher) launcher =
        g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE
                                  | G_SUBPROCESS_FLAGS_STDERR_SILENCE);
    g_autofree char *home = g_strdup_printf("HOME=%s", g_get_home_dir());
    char *env[] = { home, NULL };
    g_subprocess_launcher_set_environ(launcher, env);

    g_autoptr(GError) error = NULL;
    run->proc = g_subprocess_launcher_spawnv(launcher, (const char *const *)argv->pdata, &error);
    if (run->proc == NULL) {
        g_warning("gaudit: could not start %s: %s", GAUDIT_ORCHESTRATOR_PATH, error->message);
        finish(run);
        return NULL;
    }
    if (!interactive)
        g_output_stream_close(g_subprocess_get_stdin_pipe(run->proc), NULL, NULL);
    if (timeout_s > 0)
        run->timeout_id = g_timeout_add_seconds(timeout_s, on_timeout, run);
    g_input_stream_read_bytes_async(g_subprocess_get_stdout_pipe(run->proc), READ_CHUNK,
                                    G_PRIORITY_DEFAULT, run->cancel, on_read, run);
    return run;
}

gboolean gaudit_orchestrator_send(GauditOrchestrator *orch, const char *text)
{
    g_return_val_if_fail(orch != NULL && text != NULL, FALSE);
    if (orch->proc == NULL)
        return FALSE;
    /* A few bytes into a pipe: never blocks in practice. */
    return g_output_stream_write_all(g_subprocess_get_stdin_pipe(orch->proc), text, strlen(text),
                                     NULL, NULL, NULL);
}

void gaudit_orchestrator_close_input(GauditOrchestrator *orch)
{
    g_return_if_fail(orch != NULL);
    if (orch->proc != NULL)
        g_output_stream_close(g_subprocess_get_stdin_pipe(orch->proc), NULL, NULL);
}

void gaudit_orchestrator_stop(GauditOrchestrator *orch)
{
    g_return_if_fail(orch != NULL);
    g_cancellable_cancel(orch->cancel);
    if (orch->proc != NULL)
        g_subprocess_force_exit(orch->proc);
}
