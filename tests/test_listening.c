/* SPDX-License-Identifier: GPL-3.0-only */
/* Services listening for the network, from /proc/net/tcp and tcp6 files
 * written here in the kernel's format (little-endian words, as on x86 and
 * arm64). Never reads the real /proc. */
#include "listening.h"

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

static int remove_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

static char base[1024];

static const char *write_file(const char *name, const char *content)
{
    static char paths[4][2048];
    static int next;
    char *path = paths[next++ % 4];
    snprintf(path, sizeof paths[0], "%s/%s", base, name);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
    return path;
}

#define HEAD "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
/* One socket: local address:port (hex), state, owner. */
#define SOCK(n, addr, port, st, uid) \
    "   " #n ": " addr ":" port " 00000000:0000 " st " 00000000:00000000 00:00000000 00000000 " \
    #uid "        0 1234 1 0000000000000000 100 0 0 10 0\n"
#define SOCK6(n, addr, port, st, uid) \
    "   " #n ": " addr ":" port " 00000000000000000000000000000000:0000 " st \
    " 00000000:00000000 00:00000000 00000000 " #uid "        0 1234 1 0000000000000000 100 0 0 10 0\n"

int main(void)
{
    snprintf(base, sizeof base, "%s/listening-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    const char *tcp = write_file("tcp", HEAD
        SOCK(0, "00000000", "0016", "0A", 0)        /* sshd on 0.0.0.0:22: counts */
        SOCK(1, "0100007F", "0277", "0A", 0)        /* cupsd on 127.0.0.1:631: loopback */
        SOCK(2, "3500007F", "0035", "0A", 102)      /* resolved on 127.0.0.53: loopback */
        SOCK(3, "00000000", "E115", "0A", 1000)     /* Spotify 57621, the user's own */
        SOCK(4, "1500000A", "974D", "0A", 1000)     /* 10.0.0.21:38733, the user's own */
        SOCK(5, "1500000A", "C350", "01", 1000));   /* an established connection: not listening */
    const char *tcp6 = write_file("tcp6", HEAD
        SOCK6(0, "00000000000000000000000000000000", "0016", "0A", 0)   /* sshd on [::]:22: same service */
        SOCK6(1, "00000000000000000000000001000000", "1F90", "0A", 1000) /* [::1]:8080: loopback */
        SOCK6(2, "0000000000000000FFFF00000100007F", "1F91", "0A", 1000) /* ::ffff:127.0.0.1: loopback */
        SOCK6(3, "0000000000000000FFFF00001500000A", "1F92", "0A", 1000)); /* ::ffff:10.0.0.21: counts */

    gaudit_listening l;
    CHECK(gaudit_listening_read(tcp, tcp6, 1000, &l) == 0);
    CHECK(l.services == 4);   /* 22, 57621, 38733, 8082 */
    CHECK(l.own == 3);
    CHECK(gaudit_listening_read(tcp, tcp6, 4242, &l) == 0 && l.own == 0);

    /* Only one of the files (no IPv6), and none at all. */
    CHECK(gaudit_listening_read(tcp, "/nonexistent", 1000, &l) == 0 && l.services == 3);
    CHECK(gaudit_listening_read("/nonexistent", "/nonexistent", 1000, &l) == -1);

    /* Nothing listening. */
    const char *quiet = write_file("quiet", HEAD SOCK(0, "0100007F", "0277", "0A", 0));
    CHECK(gaudit_listening_read(quiet, NULL, 1000, &l) == 0 && l.services == 0);

    /* Malformed: never a partial count. */
    const char *bad = write_file("bad", HEAD "   0: garbage\n");
    CHECK(gaudit_listening_read(bad, NULL, 1000, &l) == -1);
    const char *nohead = write_file("nohead", SOCK(0, "00000000", "0016", "0A", 0));
    CHECK(gaudit_listening_read(nohead, NULL, 1000, &l) == -1);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s)\n", failures, base);
    else
        nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
    return failures ? 1 : 0;
}
