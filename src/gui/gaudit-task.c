/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit-task.h"
#include "gaudit-plugins.h"

#include <glib/gi18n.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

/* The built-in plugins, each in its own folder under src/plugins/. */
static const GauditTaskInfo *const tasks[] = {
    &gaudit_plugin_firewall,
    &gaudit_plugin_updates,
    &gaudit_plugin_private_files,
};

const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks)
{
    static GauditTaskInfo available[G_N_ELEMENTS(tasks)];
    static gsize n_available;
    static gsize once;
    if (g_once_init_enter(&once)) {
        const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
        for (gsize i = 0; i < G_N_ELEMENTS(tasks); i++)
            if (tasks[i]->backend == NULL || (pkg != NULL && g_strcmp0(tasks[i]->backend, pkg->name) == 0))
                available[n_available++] = *tasks[i];
        g_once_init_leave(&once, 1);
    }
    *n_tasks = n_available;
    return available;
}

const char *gaudit_task_home_command(const GauditTaskInfo *task, guint level)
{
    if (level >= GAUDIT_LEVEL_COUNT)
        level = GAUDIT_LEVEL_COUNT - 1;
    for (int l = (int)level; l >= 0; l--)
        if (task->home_commands[l] != NULL)
            return task->home_commands[l];
    if (task->home_level > 0 && task->home_level <= level)
        return task->run_command;
    return NULL;
}

guint gaudit_task_home_from(const GauditTaskInfo *task)
{
    for (guint l = 0; l < GAUDIT_LEVEL_COUNT; l++)
        if (gaudit_task_home_command(task, l) != NULL)
            return l;
    return GAUDIT_LEVEL_COUNT;
}

const GauditTaskInfo *gaudit_task_by_id(const char *id)
{
    gsize n_tasks;
    const GauditTaskInfo *all = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; id != NULL && i < n_tasks; i++)
        if (strcmp(all[i].id, id) == 0)
            return &all[i];
    return NULL;
}

const GauditTaskInfo *gaudit_task_for_command(const char *command, gsize *index)
{
    gsize n_tasks;
    const GauditTaskInfo *all = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; command != NULL && i < n_tasks; i++) {
        gboolean match = g_strcmp0(all[i].run_command, command) == 0;
        for (guint l = 0; !match && l < GAUDIT_LEVEL_COUNT; l++)
            match = g_strcmp0(all[i].home_commands[l], command) == 0;
        if (match) {
            if (index != NULL)
                *index = i;
            return &all[i];
        }
    }
    return NULL;
}

GSettings *gaudit_task_settings(const GauditTaskInfo *task)
{
    GSettingsSchemaSource *source = NULL;
    g_autoptr(GSettingsSchemaSource) own = NULL;
    if (GAUDIT_SCHEMA_DIR[0] != '\0') {
        own = g_settings_schema_source_new_from_directory(GAUDIT_SCHEMA_DIR,
                                                          g_settings_schema_source_get_default(),
                                                          FALSE, NULL);
        source = own;
    } else {
        source = g_settings_schema_source_get_default();
    }
    if (source == NULL)
        return NULL;
    g_autoptr(GSettingsSchema) schema =
        g_settings_schema_source_lookup(source, GAUDIT_APP_ID ".plugin", TRUE);
    if (schema == NULL)
        return NULL;
    /* dconf paths take [A-Za-z0-9_-]: the id's dots become dashes. */
    g_autofree char *id = g_strdelimit(g_strdup(task->id), ".", '-');
    g_autofree char *base = g_strdelimit(g_strdup(GAUDIT_APP_ID), ".", '/');
    g_autofree char *path = g_strdup_printf("/%s/plugins/%s/full/", base, id);
    return g_settings_new_full(schema, NULL, path);
}

static gboolean plain_folder(const char *f)
{
    if (f == NULL || f[0] != '/' || strlen(f) >= 256 || !g_utf8_validate(f, -1, NULL))
        return FALSE;
    for (const unsigned char *p = (const unsigned char *)f; *p != '\0'; p++)
        if (*p < 0x20 || *p == 0x7f)
            return FALSE;
    return strstr(f, "/../") == NULL && !g_str_has_suffix(f, "/..");
}

/* The home folder from the password database, as the collection uses it. */
static const char *home_folder(void)
{
    static char *home;
    if (home == NULL) {
        struct passwd *pw = getpwuid(getuid());
        home = g_strdup(pw != NULL && pw->pw_dir != NULL ? pw->pw_dir : "/");
    }
    return home;
}

static gboolean under_home(const char *path)
{
    const char *home = home_folder();
    size_t n = strlen(home);
    return strncmp(path, home, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static void add_place(GPtrArray *out, const char *path)
{
    if (path == NULL || !plain_folder(path) || under_home(path)
        || !g_file_test(path, G_FILE_TEST_IS_DIR))
        return;
    for (guint i = 0; i < out->len; i++)
        if (strcmp(g_ptr_array_index(out, i), path) == 0)
            return;
    g_ptr_array_add(out, g_strdup(path));
}

static void add_place_uri(GPtrArray *out, const char *uri)
{
    g_autofree char *path = g_filename_from_uri(uri, NULL, NULL);
    add_place(out, path);
}

/* The places a file manager shows in its sidebar. They come from the
 * user's own area, so only as candidates: the worst a planted one can do
 * is add a folder to search, and the report names every folder searched. */
static GPtrArray *file_manager_places(void)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    /* GTK file managers (Nautilus and others): "<uri> [label]" per line. */
    g_autofree char *gtk = g_build_filename(g_get_user_config_dir(), "gtk-3.0", "bookmarks", NULL);
    g_autofree char *text = NULL;
    if (g_file_get_contents(gtk, &text, NULL, NULL)) {
        g_auto(GStrv) lines = g_strsplit(text, "\n", 256);
        for (guint i = 0; lines[i] != NULL; i++) {
            char *space = strchr(lines[i], ' ');
            if (space != NULL)
                *space = '\0';
            if (g_str_has_prefix(lines[i], "file://"))
                add_place_uri(out, lines[i]);
        }
    }
    /* KDE (Dolphin): href="file://..." in an XBEL file. */
    g_autofree char *kde = g_build_filename(g_get_user_data_dir(), "user-places.xbel", NULL);
    g_autofree char *xbel = NULL;
    if (g_file_get_contents(kde, &xbel, NULL, NULL) && strlen(xbel) < 1024 * 1024) {
        for (const char *p = strstr(xbel, "href=\"file://"); p != NULL;
             p = strstr(p + 1, "href=\"file://")) {
            const char *start = p + strlen("href=\"");
            const char *end = strchr(start, '"');
            if (end == NULL)
                break;
            g_autofree char *uri = g_strndup(start, (gsize)(end - start));
            add_place_uri(out, uri);
        }
    }
    /* /mnt/<user>: an administrator's convention for a user's own space,
     * often on another disk; not in the file manager by itself. Only when
     * it belongs to the user, or it is just a folder with that name. */
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL && strchr(pw->pw_name, '/') == NULL) {
        g_autofree char *mnt = g_build_filename("/mnt", pw->pw_name, NULL);
        g_autoptr(GFile) file = g_file_new_for_path(mnt);
        g_autoptr(GFileInfo) info = g_file_query_info(file, "standard::type,unix::uid",
                                                      G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
        if (info != NULL && g_file_info_get_file_type(info) == G_FILE_TYPE_DIRECTORY
            && g_file_info_get_attribute_uint32(info, G_FILE_ATTRIBUTE_UNIX_UID) == getuid())
            add_place(out, mnt);
    }
    /* Mounted disks and network folders (GVfs mounts have a local path),
     * one by one, so one can be taken off the list and the others kept;
     * /media/<user> and /run/media/<user> themselves are only mount points. */
    GVolumeMonitor *monitor = g_volume_monitor_get();
    GList *mounts = g_volume_monitor_get_mounts(monitor);
    for (GList *m = mounts; m != NULL; m = m->next) {
        g_autoptr(GFile) root = g_mount_get_root(G_MOUNT(m->data));
        g_autofree char *path = g_file_get_path(root);
        add_place(out, path);
    }
    g_list_free_full(mounts, g_object_unref);
    g_object_unref(monitor);
    return out;
}

static GStrv checked(GStrv list)
{
    g_autoptr(GStrvBuilder) b = g_strv_builder_new();
    for (guint i = 0; list != NULL && list[i] != NULL; i++)
        if (plain_folder(list[i]))
            g_strv_builder_add(b, list[i]);
    return g_strv_builder_end(b);
}

GStrv gaudit_task_folders_split(const GauditTaskInfo *task, GStrv *places_out)
{
    g_autoptr(GStrvBuilder) out = g_strv_builder_new();
    g_autoptr(GStrvBuilder) places_b = g_strv_builder_new();
    g_autoptr(GSettings) settings = task->param_folders ? gaudit_task_settings(task) : NULL;
    if (settings != NULL) {
        g_auto(GStrv) raw = g_settings_get_strv(settings, "folders");
        g_auto(GStrv) folders = checked(raw);
        g_auto(GStrv) raw_removed = g_settings_get_strv(settings, "removed-places");
        g_auto(GStrv) removed = checked(raw_removed);
        guint n = 0;
        for (guint i = 0; folders[i] != NULL && n < GAUDIT_TASK_MAX_FOLDERS; i++, n++)
            g_strv_builder_add(out, folders[i]);
        g_autoptr(GPtrArray) places = file_manager_places();
        for (guint i = 0; i < places->len && n < GAUDIT_TASK_MAX_FOLDERS; i++) {
            const char *p = g_ptr_array_index(places, i);
            if (g_strv_contains((const char *const *)folders, p)
                || g_strv_contains((const char *const *)removed, p))
                continue;
            g_strv_builder_add(out, p);
            g_strv_builder_add(places_b, p);
            n++;
        }
    }
    if (places_out != NULL)
        *places_out = g_strv_builder_end(places_b);
    return g_strv_builder_end(out);
}

GStrv gaudit_task_folders(const GauditTaskInfo *task)
{
    return gaudit_task_folders_split(task, NULL);
}

guint gaudit_task_read_limit(const GauditTaskInfo *task)
{
    static const guint allowed[] = GAUDIT_TASK_READ_LIMITS;
    g_autoptr(GSettings) settings = task->param_read_limit ? gaudit_task_settings(task) : NULL;
    guint v = settings != NULL ? g_settings_get_uint(settings, "read-limit") : 0;
    for (gsize i = 0; i < G_N_ELEMENTS(allowed); i++)
        if (allowed[i] == v)
            return v;
    return GAUDIT_TASK_READ_LIMIT_DEFAULT;
}

void gaudit_task_set_read_limit(const GauditTaskInfo *task, guint bytes)
{
    g_autoptr(GSettings) settings = gaudit_task_settings(task);
    if (settings != NULL)
        g_settings_set_uint(settings, "read-limit", bytes);
}

void gaudit_task_reset_parameters(const GauditTaskInfo *task)
{
    g_autoptr(GSettings) settings = gaudit_task_settings(task);
    if (settings == NULL)
        return;
    static const char *const keys[] = { "folders", "removed-places", "read-limit", "with-caches" };
    for (gsize i = 0; i < G_N_ELEMENTS(keys); i++)
        g_settings_reset(settings, keys[i]);
}

gboolean gaudit_task_with_caches(const GauditTaskInfo *task)
{
    g_autoptr(GSettings) settings = task->param_caches ? gaudit_task_settings(task) : NULL;
    return settings != NULL && g_settings_get_boolean(settings, "with-caches");
}

void gaudit_task_set_with_caches(const GauditTaskInfo *task, gboolean on)
{
    g_autoptr(GSettings) settings = gaudit_task_settings(task);
    if (settings != NULL)
        g_settings_set_boolean(settings, "with-caches", on);
}

GStrv gaudit_task_run_args(const GauditTaskInfo *task)
{
    g_autoptr(GStrvBuilder) b = g_strv_builder_new();
    if (gaudit_task_with_caches(task))
        g_strv_builder_add(b, "--with-caches");
    if (task->param_read_limit) {
        g_autofree char *opt = g_strdup_printf("--read-limit=%u", gaudit_task_read_limit(task));
        g_strv_builder_add(b, opt);
    }
    g_auto(GStrv) folders = gaudit_task_folders(task);
    g_strv_builder_addv(b, (const char **)folders);
    return g_strv_builder_end(b);
}

/* list with item added (if missing) or taken away. */
static void update(GSettings *settings, const char *key, const char *item, gboolean add)
{
    g_auto(GStrv) now = g_settings_get_strv(settings, key);
    g_autoptr(GStrvBuilder) b = g_strv_builder_new();
    for (guint i = 0; now[i] != NULL; i++)
        if (strcmp(now[i], item) != 0)
            g_strv_builder_add(b, now[i]);
    if (add)
        g_strv_builder_add(b, item);
    g_auto(GStrv) next = g_strv_builder_end(b);
    g_settings_set_strv(settings, key, (const char *const *)next);
}

gboolean gaudit_task_add_folder(const GauditTaskInfo *task, const char *folder)
{
    g_autoptr(GSettings) settings = gaudit_task_settings(task);
    if (settings == NULL || !plain_folder(folder) || under_home(folder))
        return FALSE;
    g_auto(GStrv) removed = g_settings_get_strv(settings, "removed-places");
    if (g_strv_contains((const char *const *)removed, folder)) {
        update(settings, "removed-places", folder, FALSE);  /* back as a place */
        return TRUE;
    }
    update(settings, "folders", folder, TRUE);
    return TRUE;
}

void gaudit_task_remove_folder(const GauditTaskInfo *task, const char *folder)
{
    g_autoptr(GSettings) settings = gaudit_task_settings(task);
    if (settings == NULL)
        return;
    g_auto(GStrv) folders = g_settings_get_strv(settings, "folders");
    if (g_strv_contains((const char *const *)folders, folder))
        update(settings, "folders", folder, FALSE);
    else
        update(settings, "removed-places", folder, TRUE);
}

GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg)
{
    g_autoptr(GPtrArray) missing = g_ptr_array_new();

    for (const char *const *c = task->capabilities; c != NULL && *c != NULL; c++) {
        const gaudit_capability *cap = pkg->capability ? pkg->capability(*c) : NULL;
        if (cap == NULL)
            return NULL;
        if (gaudit_capability_present(cap))
            continue;
        for (const char *const *name = cap->packages; *name != NULL; name++)
            if (!g_ptr_array_find_with_equal_func(missing, *name, g_str_equal, NULL))
                g_ptr_array_add(missing, (gpointer)*name);
    }
    return g_steal_pointer(&missing);
}
