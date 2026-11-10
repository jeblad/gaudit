/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-flatpak-probe: collector for the Flatpak status on Home.
 *
 * Runs as the user, reads only local data (no network), and prints one
 * S-expression on stdout:
 *
 *   (flatpak (apps N) (eol-apps N) (eol-unused N) (eol-pinned N))
 *
 *   apps        installed apps, system and user installations
 *   eol-apps    apps that are end-of-life, or whose runtime is
 *   eol-unused  end-of-life refs that "flatpak uninstall --unused" removes
 *   eol-pinned  end-of-life runtimes no app uses that "--unused" keeps
 *               (pinned, typically installed by hand, e.g. an old SDK);
 *               only top-level runtimes are counted, never an extension
 *               of another installed runtime (.Locale, .Debug, .GL.*)
 *
 * This is the only part of gAudit linked against libflatpak, so gAudit runs
 * without the library; the caller recognises exit status 127 (the dynamic
 * loader failing) as "library missing". Any other failure exits with 1 and
 * prints nothing. */
#include <flatpak.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static gboolean ref_is_eol(FlatpakInstalledRef *ref)
{
    return flatpak_installed_ref_get_eol(ref) != NULL
        || flatpak_installed_ref_get_eol_rebase(ref) != NULL;
}

static char *ref_key(FlatpakInstalledRef *ref)
{
    FlatpakRef *r = FLATPAK_REF(ref);
    return g_strdup_printf("%s/%s/%s", flatpak_ref_get_name(r),
                           flatpak_ref_get_arch(r), flatpak_ref_get_branch(r));
}

/* "org.gnome.Platform/x86_64/48" from the app's metadata, or NULL. */
static char *app_runtime(FlatpakInstalledRef *ref)
{
    g_autoptr(GBytes) metadata = flatpak_installed_ref_load_metadata(ref, NULL, NULL);
    if (metadata == NULL)
        return NULL;
    gsize len;
    const char *data = g_bytes_get_data(metadata, &len);
    g_autoptr(GKeyFile) kf = g_key_file_new();
    if (!g_key_file_load_from_data(kf, data, len, G_KEY_FILE_NONE, NULL))
        return NULL;
    return g_key_file_get_string(kf, "Application", "runtime", NULL);
}

/* name is an extension of a runtime in names ("org.freedesktop.Sdk.Locale" of
 * "org.freedesktop.Sdk"). names holds runtime names without arch/branch. */
static gboolean is_extension(const char *name, GHashTable *names)
{
    GHashTableIter iter;
    gpointer key;
    g_hash_table_iter_init(&iter, names);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        const char *base = key;
        size_t len = strlen(base);
        if (strncmp(name, base, len) == 0 && name[len] == '.')
            return TRUE;
    }
    return FALSE;
}

#define DEFAULT_SYSTEM_DIR "/var/lib/flatpak"

/* One of installations is at path (compared after resolving symlinks). */
static gboolean has_installation_at(GPtrArray *installations, const char *path)
{
    g_autofree char *wanted = realpath(path, NULL);
    if (wanted == NULL)
        return FALSE;
    for (guint i = 0; i < installations->len; i++) {
        g_autoptr(GFile) file = flatpak_installation_get_path(installations->pdata[i]);
        g_autofree char *where = file != NULL ? g_file_get_path(file) : NULL;
        g_autofree char *resolved = where != NULL ? realpath(where, NULL) : NULL;
        if (resolved != NULL && strcmp(resolved, wanted) == 0)
            return TRUE;
    }
    return FALSE;
}

/* NULL on failure. An installation whose directory does not exist yet (a
 * user installation never used) is empty, not a failure. */
static GPtrArray *installed_refs(FlatpakInstallation *inst)
{
    g_autoptr(GError) error = NULL;
    GPtrArray *refs = flatpak_installation_list_installed_refs(inst, NULL, &error);
    if (refs != NULL)
        return refs;
    g_autoptr(GFile) path = flatpak_installation_get_path(inst);
    if (path != NULL && !g_file_query_exists(path, NULL))
        return g_ptr_array_new_with_free_func(g_object_unref);
    return NULL;
}

int main(void)
{
    g_autoptr(GPtrArray) installations = g_ptr_array_new_with_free_func(g_object_unref);

    g_autoptr(GError) error = NULL;
    g_autoptr(GPtrArray) system = flatpak_get_system_installations(NULL, &error);
    if (system == NULL)
        return 1;
    for (guint i = 0; i < system->len; i++)
        g_ptr_array_add(installations, g_object_ref(system->pdata[i]));

    /* libflatpak only warns and skips a system installation it cannot open.
     * If the default one exists on disk but is missing here, its apps would
     * silently not be counted: fail instead, so the row says unknown. */
    if (g_file_test(DEFAULT_SYSTEM_DIR, G_FILE_TEST_IS_DIR)
        && !has_installation_at(system, DEFAULT_SYSTEM_DIR))
        return 1;

    g_clear_error(&error);
    FlatpakInstallation *user = flatpak_installation_new_user(NULL, &error);
    if (user != NULL)
        g_ptr_array_add(installations, user);

    /* Pass 1: end-of-life runtimes, across all installations (an app may
     * use a runtime from another installation). */
    g_autoptr(GHashTable) eol_runtimes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_autoptr(GPtrArray) all_refs = g_ptr_array_new_with_free_func((GDestroyNotify)g_ptr_array_unref);
    for (guint i = 0; i < installations->len; i++) {
        GPtrArray *refs = installed_refs(installations->pdata[i]);
        if (refs == NULL)
            return 1;
        g_ptr_array_add(all_refs, refs);
        for (guint j = 0; j < refs->len; j++) {
            FlatpakInstalledRef *ref = refs->pdata[j];
            if (flatpak_ref_get_kind(FLATPAK_REF(ref)) == FLATPAK_REF_KIND_RUNTIME && ref_is_eol(ref))
                g_hash_table_add(eol_runtimes, ref_key(ref));
        }
    }

    /* Pass 2: apps, and the runtimes they use. */
    g_autoptr(GHashTable) used_runtimes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    unsigned apps = 0, eol_apps = 0;
    for (guint i = 0; i < all_refs->len; i++) {
        GPtrArray *refs = all_refs->pdata[i];
        for (guint j = 0; j < refs->len; j++) {
            FlatpakInstalledRef *ref = refs->pdata[j];
            if (flatpak_ref_get_kind(FLATPAK_REF(ref)) != FLATPAK_REF_KIND_APP)
                continue;
            apps++;
            g_autofree char *runtime = app_runtime(ref);
            if (ref_is_eol(ref) || (runtime != NULL && g_hash_table_contains(eol_runtimes, runtime)))
                eol_apps++;
            if (runtime != NULL)
                g_hash_table_add(used_runtimes, g_steal_pointer(&runtime));
        }
    }

    /* Unused end-of-life refs: what "flatpak uninstall --unused" removes. */
    g_autoptr(GHashTable) unused_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    unsigned eol_unused = 0;
    for (guint i = 0; i < installations->len; i++) {
        g_autoptr(GError) unused_error = NULL;
        g_autoptr(GPtrArray) unused =
            flatpak_installation_list_unused_refs(installations->pdata[i], NULL, NULL, &unused_error);
        if (unused == NULL) {
            if (((GPtrArray *)all_refs->pdata[i])->len == 0)
                continue;  /* empty installation */
            return 1;
        }
        for (guint j = 0; j < unused->len; j++) {
            g_hash_table_add(unused_keys, ref_key(unused->pdata[j]));
            if (ref_is_eol(unused->pdata[j]))
                eol_unused++;
        }
    }

    /* Names of all installed runtimes, to recognise extensions. */
    g_autoptr(GHashTable) runtime_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (guint i = 0; i < all_refs->len; i++) {
        GPtrArray *refs = all_refs->pdata[i];
        for (guint j = 0; j < refs->len; j++) {
            FlatpakRef *r = FLATPAK_REF(refs->pdata[j]);
            if (flatpak_ref_get_kind(r) == FLATPAK_REF_KIND_RUNTIME)
                g_hash_table_add(runtime_names, g_strdup(flatpak_ref_get_name(r)));
        }
    }

    /* End-of-life runtimes kept although no app uses them. */
    unsigned eol_pinned = 0;
    for (guint i = 0; i < all_refs->len; i++) {
        GPtrArray *refs = all_refs->pdata[i];
        for (guint j = 0; j < refs->len; j++) {
            FlatpakInstalledRef *ref = refs->pdata[j];
            if (flatpak_ref_get_kind(FLATPAK_REF(ref)) != FLATPAK_REF_KIND_RUNTIME || !ref_is_eol(ref))
                continue;
            g_autofree char *key = ref_key(ref);
            if (g_hash_table_contains(used_runtimes, key) || g_hash_table_contains(unused_keys, key)
                || is_extension(flatpak_ref_get_name(FLATPAK_REF(ref)), runtime_names))
                continue;
            eol_pinned++;
        }
    }

    printf("(flatpak (apps %u) (eol-apps %u) (eol-unused %u) (eol-pinned %u))\n",
           apps, eol_apps, eol_unused, eol_pinned);
    return fflush(stdout) == 0 ? 0 : 1;
}
