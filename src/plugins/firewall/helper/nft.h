/* SPDX-License-Identifier: GPL-3.0-only */
/* The nftables ruleset as the kernel holds it, read over netlink
 * (NETLINK_NETFILTER) without libnftnl, so the helper stays minimal. Needs
 * CAP_NET_ADMIN: the kernel refuses even reading the ruleset without it. */
#pragma once

#include <stddef.h>

typedef struct {
    unsigned tables;
    unsigned chains;
    unsigned input_chains;  /* base chains of type filter on the input hook (ip, ip6, inet) */
    unsigned input_drop;    /* ... of those, with policy drop */
    unsigned input_rules;   /* rules in those chains */
    unsigned rules;         /* rules in every chain */
} gaudit_nft_summary;

/* 0 on success, -1 if the ruleset could not be read. */
int gaudit_nft_read(gaudit_nft_summary *out);

/* --- Parsing, exposed for tests ------------------------------------------ */

#define GAUDIT_NFT_MAX_INPUT 64
#define GAUDIT_NFT_NAME_MAX  256  /* NFT_NAME_MAXLEN */

typedef struct {
    gaudit_nft_summary sum;
    unsigned n_input;  /* input chains remembered, to count their rules */
    struct {
        unsigned char family;
        char table[GAUDIT_NFT_NAME_MAX];
        char chain[GAUDIT_NFT_NAME_MAX];
    } input[GAUDIT_NFT_MAX_INPUT];
} gaudit_nft_collect;

/* Feeds one received buffer of a dump reply for request type msg
 * (NFT_MSG_GETTABLE, _GETCHAIN or _GETRULE, dumped in that order) with
 * sequence number seq. 1 when the dump is done, 0 when more is to come,
 * -1 on an error reply or malformed data. */
int gaudit_nft_feed(gaudit_nft_collect *c, int msg, const void *buf, size_t len, unsigned seq);
