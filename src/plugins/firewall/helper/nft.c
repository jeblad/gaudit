/* SPDX-License-Identifier: GPL-3.0-only */
#include "nft.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECV_BUF (64 * 1024)

/* Attribute iteration over [p, end). */
#define ATTR_OK(a, end) \
    ((const char *)(a) + sizeof(struct nlattr) <= (end) && (a)->nla_len >= sizeof(struct nlattr) \
     && (const char *)(a) + (a)->nla_len <= (end))
#define ATTR_NEXT(a) \
    ((const struct nlattr *)((const char *)(a) + NLA_ALIGN((a)->nla_len)))
#define ATTR_DATA(a)  ((const char *)(a) + NLA_HDRLEN)
#define ATTR_LEN(a)   ((size_t)(a)->nla_len - NLA_HDRLEN)
#define ATTR_TYPE(a)  ((a)->nla_type & NLA_TYPE_MASK)

static int attr_u32(const struct nlattr *a, unsigned *out)
{
    if (ATTR_LEN(a) != 4)
        return -1;
    uint32_t v;
    memcpy(&v, ATTR_DATA(a), 4);
    *out = ntohl(v);
    return 0;
}

/* A NUL-terminated string attribute, copied into out. */
static int attr_str(const struct nlattr *a, char *out, size_t len)
{
    size_t n = ATTR_LEN(a);
    if (n == 0 || n > len || ATTR_DATA(a)[n - 1] != '\0')
        return -1;
    memcpy(out, ATTR_DATA(a), n);
    return 0;
}

static int is_inet_family(unsigned family)
{
    return family == NFPROTO_IPV4 || family == NFPROTO_IPV6 || family == NFPROTO_INET;
}

static int on_chain(gaudit_nft_collect *c, unsigned family, const char *p, const char *end)
{
    char table[GAUDIT_NFT_NAME_MAX] = "", name[GAUDIT_NFT_NAME_MAX] = "", type[32] = "";
    int has_hook = 0, has_policy = 0;
    unsigned hooknum = 0, policy = 0;
    for (const struct nlattr *a = (const struct nlattr *)p; ATTR_OK(a, end); a = ATTR_NEXT(a)) {
        switch (ATTR_TYPE(a)) {
        case NFTA_CHAIN_TABLE:
            if (attr_str(a, table, sizeof table) != 0)
                return -1;
            break;
        case NFTA_CHAIN_NAME:
            if (attr_str(a, name, sizeof name) != 0)
                return -1;
            break;
        case NFTA_CHAIN_TYPE:
            if (attr_str(a, type, sizeof type) != 0)
                return -1;
            break;
        case NFTA_CHAIN_POLICY:
            if (attr_u32(a, &policy) != 0)
                return -1;
            has_policy = 1;
            break;
        case NFTA_CHAIN_HOOK: {
            const char *hend = (const char *)a + a->nla_len;
            for (const struct nlattr *h = (const struct nlattr *)ATTR_DATA(a); ATTR_OK(h, hend);
                 h = ATTR_NEXT(h))
                if (ATTR_TYPE(h) == NFTA_HOOK_HOOKNUM) {
                    if (attr_u32(h, &hooknum) != 0)
                        return -1;
                    has_hook = 1;
                }
            break;
        }
        default:
            break;
        }
    }
    c->sum.chains++;
    if (!has_hook || !is_inet_family(family) || hooknum != NF_INET_LOCAL_IN
        || strcmp(type, "filter") != 0)
        return 0;
    c->sum.input_chains++;
    if (has_policy && policy == NF_DROP)
        c->sum.input_drop++;
    if (c->n_input < GAUDIT_NFT_MAX_INPUT) {
        c->input[c->n_input].family = (unsigned char)family;
        memcpy(c->input[c->n_input].table, table, sizeof table);
        memcpy(c->input[c->n_input].chain, name, sizeof name);
        c->n_input++;
    }
    return 0;
}

static int on_rule(gaudit_nft_collect *c, unsigned family, const char *p, const char *end)
{
    char table[GAUDIT_NFT_NAME_MAX] = "", chain[GAUDIT_NFT_NAME_MAX] = "";
    for (const struct nlattr *a = (const struct nlattr *)p; ATTR_OK(a, end); a = ATTR_NEXT(a)) {
        if (ATTR_TYPE(a) == NFTA_RULE_TABLE && attr_str(a, table, sizeof table) != 0)
            return -1;
        if (ATTR_TYPE(a) == NFTA_RULE_CHAIN && attr_str(a, chain, sizeof chain) != 0)
            return -1;
    }
    c->sum.rules++;
    for (unsigned i = 0; i < c->n_input; i++)
        if (c->input[i].family == family && strcmp(c->input[i].table, table) == 0
            && strcmp(c->input[i].chain, chain) == 0) {
            c->sum.input_rules++;
            break;
        }
    return 0;
}

int gaudit_nft_feed(gaudit_nft_collect *c, int msg, const void *buf, size_t len, unsigned seq)
{
    int reply = msg == NFT_MSG_GETTABLE ? NFT_MSG_NEWTABLE
              : msg == NFT_MSG_GETCHAIN ? NFT_MSG_NEWCHAIN
              : msg == NFT_MSG_GETRULE  ? NFT_MSG_NEWRULE : -1;
    if (c == NULL || buf == NULL || reply < 0)
        return -1;
    const struct nlmsghdr *nh = buf;
    size_t left = len;
    for (; NLMSG_OK(nh, left); nh = NLMSG_NEXT(nh, left)) {
        if (nh->nlmsg_seq != seq)
            return -1;
        if (nh->nlmsg_type == NLMSG_DONE)
            return 1;
        if (nh->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *err = NLMSG_DATA(nh);
            if (nh->nlmsg_len < NLMSG_LENGTH(sizeof *err) || err->error != 0)
                return -1;
            continue;  /* an acknowledgement */
        }
        if (nh->nlmsg_type != ((NFNL_SUBSYS_NFTABLES << 8) | reply)
            || nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg)))
            return -1;
        const struct nfgenmsg *g = NLMSG_DATA(nh);
        const char *p = (const char *)g + NLMSG_ALIGN(sizeof *g);
        const char *end = (const char *)nh + nh->nlmsg_len;
        int r = 0;
        if (reply == NFT_MSG_NEWTABLE)
            c->sum.tables++;
        else if (reply == NFT_MSG_NEWCHAIN)
            r = on_chain(c, g->nfgen_family, p, end);
        else
            r = on_rule(c, g->nfgen_family, p, end);
        if (r != 0)
            return -1;
    }
    return left == 0 ? 0 : -1;  /* trailing bytes: malformed */
}

static int dump(int fd, gaudit_nft_collect *c, int msg, unsigned seq)
{
    struct {
        struct nlmsghdr nh;
        struct nfgenmsg g;
    } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof req.g);
    req.nh.nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | msg;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = seq;
    req.g.nfgen_family = NFPROTO_UNSPEC;
    req.g.version = NFNETLINK_V0;

    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof kernel) < 0)
        return -1;

    static char buf[RECV_BUF] __attribute__((aligned(NLMSG_ALIGNTO)));
    for (int rounds = 0; rounds < 100000; rounds++) {
        struct sockaddr_nl from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || fromlen != sizeof from || from.nl_pid != 0)
            return -1;  /* error, or not from the kernel */
        int r = gaudit_nft_feed(c, msg, buf, (size_t)n, seq);
        if (r != 0)
            return r > 0 ? 0 : -1;
    }
    return -1;
}

int gaudit_nft_read(gaudit_nft_summary *out)
{
    if (out == NULL)
        return -1;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return -1;
    static gaudit_nft_collect c;
    memset(&c, 0, sizeof c);
    /* Chains before rules, so rules can be matched to the input chains. */
    int ok = dump(fd, &c, NFT_MSG_GETTABLE, 1) == 0
          && dump(fd, &c, NFT_MSG_GETCHAIN, 2) == 0
          && dump(fd, &c, NFT_MSG_GETRULE, 3) == 0;
    close(fd);
    if (!ok)
        return -1;
    *out = c.sum;
    return 0;
}
