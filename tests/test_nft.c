/* SPDX-License-Identifier: GPL-3.0-only */
/* The helper's nftables reader: dump replies built by hand, as the kernel
 * sends them, and that reading the real ruleset fails closed without
 * CAP_NET_ADMIN. */
#include "nft.h"

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
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

/* A reply buffer being built: messages appended one after another. */
static char buf[8192] __attribute__((aligned(4)));
static size_t used;
static struct nlmsghdr *cur;

static void msg_begin(int type, int family, unsigned seq)
{
    cur = (struct nlmsghdr *)(buf + used);
    memset(cur, 0, NLMSG_LENGTH(sizeof(struct nfgenmsg)));
    cur->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    cur->nlmsg_type = (uint16_t)type;
    cur->nlmsg_seq = seq;
    struct nfgenmsg *g = NLMSG_DATA(cur);
    g->nfgen_family = (uint8_t)family;
    g->version = NFNETLINK_V0;
}

static struct nlattr *attr(int type, const void *data, size_t len)
{
    struct nlattr *a = (struct nlattr *)((char *)cur + NLMSG_ALIGN(cur->nlmsg_len));
    a->nla_type = (uint16_t)type;
    a->nla_len = (uint16_t)(NLA_HDRLEN + len);
    if (len > 0)
        memcpy((char *)a + NLA_HDRLEN, data, len);
    memset((char *)a + NLA_HDRLEN + len, 0, NLA_ALIGN(a->nla_len) - a->nla_len);
    cur->nlmsg_len = NLMSG_ALIGN(cur->nlmsg_len) + NLA_ALIGN(a->nla_len);
    return a;
}

static void attr_str(int type, const char *s)
{
    attr(type, s, strlen(s) + 1);
}

static void attr_u32(int type, unsigned v)
{
    uint32_t be = htonl(v);
    attr(type, &be, 4);
}

static void msg_end(void)
{
    used += NLMSG_ALIGN(cur->nlmsg_len);
}

static void done(unsigned seq)
{
    cur = (struct nlmsghdr *)(buf + used);
    memset(cur, 0, NLMSG_LENGTH(4));
    cur->nlmsg_len = NLMSG_LENGTH(4);
    cur->nlmsg_type = NLMSG_DONE;
    cur->nlmsg_seq = seq;
    used += NLMSG_ALIGN(cur->nlmsg_len);
}

#define NFT(t) ((NFNL_SUBSYS_NFTABLES << 8) | (t))

static void chain(int family, const char *table, const char *name, const char *type,
                  int hook, int policy, unsigned seq)
{
    msg_begin(NFT(NFT_MSG_NEWCHAIN), family, seq);
    attr_str(NFTA_CHAIN_TABLE, table);
    attr_str(NFTA_CHAIN_NAME, name);
    if (hook >= 0) {
        /* Nested: NFTA_CHAIN_HOOK holding NFTA_HOOK_HOOKNUM and _PRIORITY. */
        struct nlattr *h = attr(NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
        size_t start = cur->nlmsg_len;
        attr_u32(NFTA_HOOK_HOOKNUM, (unsigned)hook);
        attr_u32(NFTA_HOOK_PRIORITY, 0);
        h->nla_len = (uint16_t)(NLA_HDRLEN + (cur->nlmsg_len - start));
        attr_str(NFTA_CHAIN_TYPE, type);
    }
    if (policy >= 0)
        attr_u32(NFTA_CHAIN_POLICY, (unsigned)policy);
    msg_end();
}

static void rule(int family, const char *table, const char *chain_name, unsigned seq)
{
    msg_begin(NFT(NFT_MSG_NEWRULE), family, seq);
    attr_str(NFTA_RULE_TABLE, table);
    attr_str(NFTA_RULE_CHAIN, chain_name);
    msg_end();
}

int main(void)
{
    static gaudit_nft_collect c;
    memset(&c, 0, sizeof c);

    /* Tables. */
    used = 0;
    msg_begin(NFT(NFT_MSG_NEWTABLE), NFPROTO_IPV4, 1);
    attr_str(NFTA_TABLE_NAME, "filter");
    msg_end();
    msg_begin(NFT(NFT_MSG_NEWTABLE), NFPROTO_INET, 1);
    attr_str(NFTA_TABLE_NAME, "firewalld");
    msg_end();
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETTABLE, buf, used, 1) == 0);  /* more to come */
    used = 0;
    done(1);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETTABLE, buf, used, 1) == 1);
    CHECK(c.sum.tables == 2);

    /* Chains: what ufw (iptables-nft) and firewalld set up, plus some that
     * are not input filters. */
    used = 0;
    chain(NFPROTO_IPV4, "filter", "INPUT", "filter", NF_INET_LOCAL_IN, NF_DROP, 2);     /* input, drop */
    chain(NFPROTO_INET, "firewalld", "filter_INPUT", "filter", NF_INET_LOCAL_IN, NF_ACCEPT, 2);
    chain(NFPROTO_IPV4, "filter", "FORWARD", "filter", NF_INET_FORWARD, NF_DROP, 2);
    chain(NFPROTO_IPV4, "nat", "INPUT", "nat", NF_INET_LOCAL_IN, NF_ACCEPT, 2);         /* nat, not filter */
    chain(NFPROTO_BRIDGE, "br", "in", "filter", NF_INET_LOCAL_IN, NF_DROP, 2);          /* not ip */
    chain(NFPROTO_IPV4, "filter", "ufw-user-input", "", -1, -1, 2);                     /* regular chain */
    done(2);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETCHAIN, buf, used, 2) == 1);
    CHECK(c.sum.chains == 6);
    CHECK(c.sum.input_chains == 2);
    CHECK(c.sum.input_drop == 1);

    /* Rules: counted in every chain, and separately in the input chains. */
    used = 0;
    rule(NFPROTO_IPV4, "filter", "INPUT", 3);
    rule(NFPROTO_IPV4, "filter", "INPUT", 3);
    rule(NFPROTO_INET, "firewalld", "filter_INPUT", 3);
    rule(NFPROTO_IPV4, "filter", "ufw-user-input", 3);
    rule(NFPROTO_IPV6, "filter", "INPUT", 3);   /* other family: not the ip INPUT chain */
    done(3);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used, 3) == 1);
    CHECK(c.sum.rules == 5);
    CHECK(c.sum.input_rules == 3);

    /* Malformed or unexpected replies are errors, never partial counts. */
    used = 0;
    rule(NFPROTO_IPV4, "filter", "INPUT", 9);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used, 3) == -1);     /* wrong sequence */
    used = 0;
    chain(NFPROTO_IPV4, "filter", "INPUT", "filter", NF_INET_LOCAL_IN, NF_DROP, 3);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used, 3) == -1);     /* chain in a rule dump */
    used = 0;
    rule(NFPROTO_IPV4, "filter", "INPUT", 3);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used - 1, 3) == -1); /* cut short */
    used = 0;
    msg_begin(NFT(NFT_MSG_NEWRULE), NFPROTO_IPV4, 3);
    attr(NFTA_RULE_TABLE, "filter", 6);                                  /* no terminating NUL */
    msg_end();
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used, 3) == -1);
    used = 0;
    cur = (struct nlmsghdr *)buf;
    memset(cur, 0, NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    cur->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
    cur->nlmsg_type = NLMSG_ERROR;
    cur->nlmsg_seq = 3;
    ((struct nlmsgerr *)NLMSG_DATA(cur))->error = -1;                    /* -EPERM */
    used = NLMSG_ALIGN(cur->nlmsg_len);
    CHECK(gaudit_nft_feed(&c, NFT_MSG_GETRULE, buf, used, 3) == -1);
    CHECK(gaudit_nft_feed(&c, 12345, buf, used, 3) == -1);               /* unknown request */

    /* Without CAP_NET_ADMIN the kernel refuses, and the reader says so. */
    if (geteuid() != 0) {
        gaudit_nft_summary s;
        CHECK(gaudit_nft_read(&s) == -1);
    }

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
