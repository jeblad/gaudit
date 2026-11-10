/* SPDX-License-Identifier: GPL-3.0-only */
#include "listening.h"

#include "gaudit/backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define MAX_LINES 200000
#define TCP_LISTEN 0x0A

typedef struct {
    unsigned char any[65536 / 8];
    unsigned char own[65536 / 8];
} port_sets;

static int hexpair(const char *p)
{
    char b[3] = { p[0], p[1], '\0' };
    return (int)strtoul(b, NULL, 16);
}

static int little_endian(void)
{
    static const unsigned one = 1;
    return *(const unsigned char *)&one;
}

/* The kernel prints each 32-bit word of the address in host byte order;
 * on little-endian machines the first octet is the word's last pair. */
static int word_first_octet(const char *word)
{
    return little_endian() ? hexpair(word + 6) : hexpair(word);
}

static int is_loopback(const char *addr, size_t len)
{
    if (len == 8)
        return word_first_octet(addr) == 127;
    if (len != 32)
        return 0;
    /* ::1 */
    if (strncmp(addr, "000000000000000000000000", 24) == 0)
        return strncmp(addr + 24, little_endian() ? "01000000" : "00000001", 8) == 0;
    /* ::ffff:127.x.x.x */
    return strncmp(addr, "0000000000000000", 16) == 0
           && strncasecmp(addr + 16, little_endian() ? "FFFF0000" : "0000FFFF", 8) == 0
           && word_first_octet(addr + 24) == 127;
}

/* 1 read, 0 missing, -1 malformed. */
static int read_file(const char *path, uid_t uid, port_sets *sets)
{
    if (path == NULL)
        return 0;
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return 0;
    char line[512];
    int n = 0, bad = 0;
    if (fgets(line, sizeof line, f) == NULL || strstr(line, "local_address") == NULL)
        bad = 1;  /* not the header we know */
    while (!bad && fgets(line, sizeof line, f) != NULL) {
        if (++n > MAX_LINES) {
            bad = 1;
            break;
        }
        char addr[40];
        unsigned port, state, owner;
        if (sscanf(line, " %*u: %39[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x %*x:%*x %*x:%*x %*x %u",
                   addr, &port, &state, &owner) != 4 || port > 65535) {
            bad = 1;
            break;
        }
        if (state != TCP_LISTEN || is_loopback(addr, strlen(addr)))
            continue;
        sets->any[port / 8] |= (unsigned char)(1u << (port % 8));
        if (owner == uid)
            sets->own[port / 8] |= (unsigned char)(1u << (port % 8));
    }
    fclose(f);
    return bad ? -1 : 1;
}

int gaudit_listening_read(const char *tcp, const char *tcp6, uid_t uid, gaudit_listening *out)
{
    if (out == NULL)
        return -1;
    static port_sets sets;
    memset(&sets, 0, sizeof sets);
    int a = read_file(tcp, uid, &sets);
    int b = read_file(tcp6, uid, &sets);
    if (a < 0 || b < 0 || (a == 0 && b == 0))
        return -1;
    out->services = out->own = 0;
    for (size_t i = 0; i < sizeof sets.any; i++) {
        out->services += (unsigned)__builtin_popcount(sets.any[i]);
        out->own += (unsigned)__builtin_popcount(sets.own[i]);
    }
    return 0;
}

gaudit_backend_status gaudit_listening_here(unsigned *out_services, unsigned *out_own)
{
    if (out_services == NULL || out_own == NULL)
        return GAUDIT_BACKEND_ERROR;
    gaudit_listening l;
    if (gaudit_listening_read("/proc/net/tcp", "/proc/net/tcp6", getuid(), &l) != 0)
        return GAUDIT_BACKEND_ERROR;
    *out_services = l.services;
    *out_own = l.own;
    return GAUDIT_BACKEND_OK;
}
