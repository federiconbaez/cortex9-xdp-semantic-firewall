// SPDX-License-Identifier: GPL-2.0
// fnbr XDP semantic firewall — kernel side.
//
// Lo que hace (y nada más):
//   1. Parsea Ethernet -> IPv4 -> TCP (sin opciones IP raras, sin IPv6 todavía).
//   2. Solo mira flujos cuyo puerto (src o dst) está en `watch_ports`.
//   3. Si el flujo ya está en `blocked`, XDP_DROP (corte de conexión: los
//      segmentos y retransmisiones se descartan; NO se envía RST).
//   4. Copia hasta SCAN_LEN bytes del payload TCP en claro a un buffer per-CPU
//      y busca, sin distinguir mayúsculas, los patrones de `patterns`.
//   5. Si hay coincidencia: bloquea el flujo (ambas direcciones), cuenta y
//      emite un evento al ring buffer; XDP_DROP.
//   6. Si no hay coincidencia, emite el prefijo al ring buffer para el
//      clasificador semántico en espacio de usuario (que puede bloquear el
//      flujo escribiendo en `blocked`), y XDP_PASS.
//
// Límites duros: no ve TLS descifrado, no reensambla TCP ni HTTP/2, no ve
// tráfico stdio. Ver LIMITES.md.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SCAN_LEN     256   /* bytes de payload inspeccionados en kernel */
#define PAT_MAX_LEN  32
#define MAX_PATTERNS 8
#define EVT_PREFIX   192   /* bytes del payload que se mandan a userspace */

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct pattern {
    __u32 len;                 /* 0 = slot vacío */
    __u8  bytes[PAT_MAX_LEN];  /* en minúsculas, ceros después de len */
};

struct scratch {
    __u32 len;
    __u8  buf[SCAN_LEN + PAT_MAX_LEN];
};

struct event {
    struct flow_key flow;
    __u32 payload_len;     /* longitud real del payload TCP del segmento */
    __u32 copied;          /* bytes copiados en `prefix` */
    __s32 pattern_id;      /* -1 si no hubo coincidencia en kernel */
    __u32 action;          /* XDP_PASS / XDP_DROP */
    __u8  prefix[EVT_PREFIX];
};

enum stat_idx {
    ST_SEEN = 0, ST_WATCHED, ST_DROP_PATTERN, ST_DROP_BLOCKED, ST_PASS, ST_EVT_LOST, ST_MAX
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, __u16); __type(value, __u8); } watch_ports SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MAX_PATTERNS);
         __type(key, __u32); __type(value, struct pattern); } patterns SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 16384);
         __type(key, struct flow_key); __type(value, __u32); } blocked SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, struct scratch); } scratch_map SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, ST_MAX);
         __type(key, __u32); __type(value, __u64); } stats SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) (*v)++;
}

/* Minúscula ASCII. */
static __always_inline __u8 lower(__u8 c)
{
    __u8 is_upper = (__u8)((__u8)(c - 'A') < 26);
    return c | (is_upper << 5);
}

struct match_ctx {
    __u32 payload_len;
    __s32 hit;
};

/* Callback de bpf_loop. idx = offset * MAX_PATTERNS + patrón.
 * Compara un patrón en un offset. */
static long match_at(__u64 idx, void *data)
{
    struct match_ctx *m = data;
    __u32 zero = 0;
    __u32 key = idx & (MAX_PATTERNS - 1);
    __u32 o = (idx / MAX_PATTERNS) & (SCAN_LEN - 1);

    struct scratch *s = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!s)
        return 1;
    struct pattern *pat = bpf_map_lookup_elem(&patterns, &key);
    if (!pat)
        return 0;
    __u32 plen = pat->len;
    if (plen == 0 || plen > PAT_MAX_LEN)
        return 0;
    if (o + plen > s->len)
        return 0;

    __u8 diff = 0;
    /* Bucle acotado SIN desenrollar: el verificador lo recorre como
     * máximo PAT_MAX_LEN veces por patrón y offset. */
#pragma clang loop unroll(disable)
    for (__u32 j = 0; j < PAT_MAX_LEN; j++) {
        if (j >= plen)
            break;
        diff |= lower(s->buf[o + j]) ^ pat->bytes[j];
        if (diff)
            break;
    }
    if (diff == 0) {
        m->hit = (__s32)key;
        return 1; /* cortar el loop */
    }
    return 0;
}

static __always_inline void block_flow(struct flow_key *k)
{
    __u32 one = 1;
    struct flow_key rev = { .saddr = k->daddr, .daddr = k->saddr,
                            .sport = k->dport, .dport = k->sport };
    bpf_map_update_elem(&blocked, k, &one, BPF_ANY);
    bpf_map_update_elem(&blocked, &rev, &one, BPF_ANY);
}

SEC("xdp")
int fnbr_xdp_fw(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bump(ST_SEEN);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    __u32 thl = tcp->doff * 4;
    if (thl < sizeof(*tcp))
        return XDP_PASS;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    if (!bpf_map_lookup_elem(&watch_ports, &sport) &&
        !bpf_map_lookup_elem(&watch_ports, &dport))
        return XDP_PASS;
    bump(ST_WATCHED);

    struct flow_key k = { .saddr = ip->saddr, .daddr = ip->daddr,
                          .sport = sport, .dport = dport };
    if (bpf_map_lookup_elem(&blocked, &k)) {
        bump(ST_DROP_BLOCKED);
        return XDP_DROP;
    }

    __u32 tot = bpf_ntohs(ip->tot_len);
    if (tot < ihl + thl)
        return XDP_PASS;
    __u32 plen = tot - ihl - thl;
    if (plen == 0) {
        bump(ST_PASS);
        return XDP_PASS;
    }

    __u32 zero = 0;
    struct scratch *s = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!s)
        return XDP_PASS;

    __u32 off = sizeof(*eth) + ihl + thl;
    __u32 n = plen > SCAN_LEN ? SCAN_LEN : plen;
    /* Forzar n en [1, SCAN_LEN] de forma que el verificador lo vea. */
    n = ((n - 1) & (SCAN_LEN - 1)) + 1;
    asm volatile("" : "+r"(n));
    if (n < 1 || n > SCAN_LEN)
        return XDP_PASS;
    if (bpf_xdp_load_bytes(ctx, off, s->buf, n) < 0)
        return XDP_PASS;
    s->len = n;

    struct match_ctx m = { .payload_len = n, .hit = -1 };
    bpf_loop(n * MAX_PATTERNS, match_at, &m, 0);

    __u32 action = XDP_PASS;
    if (m.hit >= 0) {
        block_flow(&k);
        bump(ST_DROP_PATTERN);
        action = XDP_DROP;
    } else {
        bump(ST_PASS);
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump(ST_EVT_LOST);
        return action;
    }
    e->flow = k;
    e->payload_len = plen;
    __u32 c = n > EVT_PREFIX ? EVT_PREFIX : n;
    e->copied = c;
    e->pattern_id = m.hit;
    e->action = action;
    __builtin_memset(e->prefix, 0, EVT_PREFIX);
    if (c > 0 && c <= EVT_PREFIX)
        bpf_probe_read_kernel(e->prefix, c, s->buf);
    bpf_ringbuf_submit(e, 0);
    return action;
}

char LICENSE[] SEC("license") = "GPL";
