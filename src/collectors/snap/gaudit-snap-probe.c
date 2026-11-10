/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-snap-probe: collector for the Snap status on Home.
 *
 * Asks snapd's REST API on /run/snapd.socket (readable without privileges,
 * local only) and prints one S-expression on stdout:
 *
 *   (snap (running N) (snaps N) (devmode N) (classic N) (held N)
 *         (last-refresh EPOCH) (refresh-hold EPOCH))
 *
 *   running        1 if snapd answered, else 0 (then the rest is 0)
 *   snaps          installed snaps
 *   devmode        snaps in developer mode: sandbox violations only logged
 *   classic        snaps with classic confinement: no sandbox, by design
 *   held           snaps the user has held back from refreshes
 *   last-refresh   time of the last automatic refresh, 0 if unknown
 *   refresh-hold   automatic refreshes held system-wide until then, 0 if not
 *
 * This is the only part of gAudit linked against json-glib; exit status
 * 127 (the dynamic loader failing) means a library is missing. Any other
 * failure exits with 1 and prints nothing. */
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <json-glib/json-glib.h>
#include <stdio.h>
#include <string.h>

#define SOCKET_PATH  "/run/snapd.socket"
#define MAX_RESPONSE (8 * 1024 * 1024)

/* One HTTP/1.0 GET over the socket; the server closes the connection after
 * the response. Returns the body, or NULL. */
static char *http_get(const char *path)
{
    g_autoptr(GSocketClient) client = g_socket_client_new();
    g_socket_client_set_timeout(client, 3);
    g_autoptr(GSocketAddress) address = g_unix_socket_address_new(SOCKET_PATH);
    g_autoptr(GSocketConnection) conn =
        g_socket_client_connect(client, G_SOCKET_CONNECTABLE(address), NULL, NULL);
    if (conn == NULL)
        return NULL;

    g_autofree char *request = g_strdup_printf("GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n", path);
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    if (!g_output_stream_write_all(out, request, strlen(request), NULL, NULL, NULL))
        return NULL;

    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(conn));
    g_autoptr(GByteArray) response = g_byte_array_new();
    guint8 chunk[16384];
    for (;;) {
        gssize n = g_input_stream_read(in, chunk, sizeof chunk, NULL, NULL);
        if (n < 0)
            return NULL;
        if (n == 0)
            break;
        if (response->len + (gsize)n > MAX_RESPONSE)
            return NULL;
        g_byte_array_append(response, chunk, (guint)n);
    }
    g_byte_array_append(response, (const guint8 *)"", 1);

    const char *text = (const char *)response->data;
    if (strncmp(text, "HTTP/1.", 7) != 0 || strncmp(text + 8, " 200 ", 5) != 0)
        return NULL;
    const char *body = strstr(text, "\r\n\r\n");
    return body != NULL ? g_strdup(body + 4) : NULL;
}

/* The "result" member of snapd's response envelope, or NULL. */
static JsonNode *result_of(JsonParser *parser, const char *body)
{
    if (body == NULL || !json_parser_load_from_data(parser, body, -1, NULL))
        return NULL;
    JsonNode *root = json_parser_get_root(parser);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root))
        return NULL;
    JsonObject *obj = json_node_get_object(root);
    return json_object_has_member(obj, "result") ? json_object_get_member(obj, "result") : NULL;
}

/* RFC 3339 time to seconds since epoch; 0 if absent or unparsable. */
static gint64 epoch_of(JsonObject *obj, const char *member)
{
    if (obj == NULL || !json_object_has_member(obj, member))
        return 0;
    const char *text = json_object_get_string_member(obj, member);
    if (text == NULL)
        return 0;
    g_autoptr(GDateTime) dt = g_date_time_new_from_iso8601(text, NULL);
    gint64 t = dt != NULL ? g_date_time_to_unix(dt) : 0;
    return t > 0 ? t : 0;
}

int main(void)
{
    g_autofree char *info_body = http_get("/v2/system-info");
    if (info_body == NULL) {
        /* No answer: snapd is not running (or not reachable). */
        printf("(snap (running 0) (snaps 0) (devmode 0) (classic 0) (held 0)"
               " (last-refresh 0) (refresh-hold 0))\n");
        return fflush(stdout) == 0 ? 0 : 1;
    }

    g_autoptr(JsonParser) info_parser = json_parser_new();
    JsonNode *info = result_of(info_parser, info_body);
    if (info == NULL || !JSON_NODE_HOLDS_OBJECT(info))
        return 1;
    JsonObject *info_obj = json_node_get_object(info);
    JsonObject *refresh = json_object_has_member(info_obj, "refresh")
        ? json_object_get_object_member(info_obj, "refresh") : NULL;
    gint64 last_refresh = epoch_of(refresh, "last");
    gint64 refresh_hold = epoch_of(refresh, "hold");

    g_autofree char *snaps_body = http_get("/v2/snaps");
    g_autoptr(JsonParser) snaps_parser = json_parser_new();
    JsonNode *snaps = result_of(snaps_parser, snaps_body);
    if (snaps == NULL || !JSON_NODE_HOLDS_ARRAY(snaps))
        return 1;

    unsigned n_snaps = 0, devmode = 0, classic = 0, held = 0;
    JsonArray *list = json_node_get_array(snaps);
    for (guint i = 0; i < json_array_get_length(list); i++) {
        JsonNode *node = json_array_get_element(list, i);
        if (!JSON_NODE_HOLDS_OBJECT(node))
            continue;
        JsonObject *snap = json_node_get_object(node);  /* top-level fields only */
        n_snaps++;
        const char *confinement = json_object_has_member(snap, "confinement")
            ? json_object_get_string_member(snap, "confinement") : NULL;
        gboolean is_devmode = json_object_has_member(snap, "devmode")
            && json_object_get_boolean_member(snap, "devmode");
        if (is_devmode || g_strcmp0(confinement, "devmode") == 0)
            devmode++;
        else if (g_strcmp0(confinement, "classic") == 0)
            classic++;
        if (json_object_has_member(snap, "hold"))
            held++;
    }

    printf("(snap (running 1) (snaps %u) (devmode %u) (classic %u) (held %u)"
           " (last-refresh %" G_GINT64_FORMAT ") (refresh-hold %" G_GINT64_FORMAT "))\n",
           n_snaps, devmode, classic, held, last_refresh, refresh_hold);
    return fflush(stdout) == 0 ? 0 : 1;
}
