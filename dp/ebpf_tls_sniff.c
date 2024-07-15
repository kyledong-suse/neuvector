#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"
#include "dpi/dpi_packet.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tls_sniff.skel.h"
#include "ebpf_common.h"

#define MAX_EBPF_TLS_BUF_SIZE 65536
static uint8_t g_ebpf_tls_rx_buf[MAX_EBPF_TLS_BUF_SIZE];

int save_link_to_skeleton(struct tls_sniff_bpf *skel, const char *prog_name, struct bpf_link *link)
{
    if (strcmp(prog_name, "probe_ssl_read")) {
        skel->links.probe_ssl_read = link;
    } else if (strcmp(prog_name, "probe_ssl_write")) {
        skel->links.probe_ssl_write = link;
    } else if (strcmp(prog_name, "probe_ret_ssl_read")) {
        skel->links.probe_ret_ssl_read = link;
    } else if (strcmp(prog_name, "probe_ret_ssl_write")) {
        skel->links.probe_ret_ssl_write = link;
    } else {
        DEBUG_ERROR(DBG_CTRL, "Unknown program name '%s\n", prog_name);
        return -1;
    }

    return 0;
}

int attach_uprobe(struct tls_sniff_bpf *skel, const char *lib, const char *func_name, const char *prog_name, bool is_retprobe)
{
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = func_name, .retprobe = is_retprobe);
    struct bpf_link *link;
    struct bpf_program *prog;

    // Find the program by name
    prog = bpf_object__find_program_by_name(skel->obj, prog_name);
    if (!prog) {
        DEBUG_ERROR(DBG_CTRL, "fail to find program '%s'\n", prog_name);
        return -1;
    }

    // Attach uprobe
    link = bpf_program__attach_uprobe_opts(prog, -1, lib, 0, &uprobe_opts);
    if (!link) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach uprobe\n");
        return -1;
    }

    if (save_link_to_skeleton(skel, prog_name, link)) {
        DEBUG_ERROR(DBG_CTRL, "fail to save link for program '%s'\n", prog_name);
        bpf_link__destroy(link);
        return -1;
    }

    return 0;
}

static int attach_openssl(struct tls_sniff_bpf *skel, const char *lib)
{
    if (attach_uprobe(skel, lib, "SSL_read", "probe_ssl_read", false)) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach probe_ssl_read to SSL_read\n");
        return -1;
    }

    if (attach_uprobe(skel, lib, "SSL_write", "probe_ssl_write", false)) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach probe_ssl_write to SSL_write\n");
        return -1;
    }
    
    if (attach_uprobe(skel, lib, "SSL_read", "probe_ret_ssl_read", true)) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach probe_ret_ssl_read to SSL_read\n");
        return -1;
    }

    if (attach_uprobe(skel, lib, "SSL_write", "probe_ret_ssl_write", true)) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach probe_ret_ssl_write to SSL_write\n");
        return -1;
    }

    return 0;
}

// static void print_tls_plain_text(struct probe_tls_sniff_event_t *event)
// {
//     char buf[MAX_BUF_SIZE + 1] = {0};
//     uint32_t buf_size;
//     char *tls_event_type_str[2][2] = {
//         {"SSL_READ", "RECEIVE"},
//         {"SSL_WRITE", "SEND"}
//     };

//     if (event->len <= MAX_BUF_SIZE) {
//         buf_size = event->len;
//     } else {
//         buf_size = MAX_BUF_SIZE;
//     }

//     memcpy(buf, event->buf, buf_size);

//     dp_ebpf_tcp_pkt_entry_t *entry = rcu_map_lookup(&g_ebpf_tcp_pkt_map, &event->pid);
//     if (entry) {
//         char src[INET6_ADDRSTRLEN];
//         char dst[INET6_ADDRSTRLEN];
//         union {
//             struct in_addr ipv4;
//             struct in6_addr ipv6;
//         } s, d;

//         if (entry->r->sa_af == AF_INET) {
//             s.ipv4.s_addr = entry->r->saddr_v4;
//             d.ipv4.s_addr = entry->r->daddr_v4;
//         } else if (entry->r->sa_af == AF_INET6) {
//             memcpy(&s.ipv6.s6_addr, entry->r->saddr_v6, sizeof(s.ipv6.s6_addr));
//             memcpy(&d.ipv6.s6_addr, entry->r->daddr_v6, sizeof(d.ipv6.s6_addr));
//         }

//         DEBUG_CTRL("pid:%d, comm:%s, %s, src:%s, lport:%d, dst:%s, dport:%d, seq:%d, ack_seq:%d", 
//                    entry->r->pid, entry->r->comm, entry->r->sa_af == AF_INET ? "IPv4" : "IPv6", 
//                    inet_ntop(entry->r->sa_af, &s, src, sizeof(src)), ntohs(entry->r->lport), 
//                    inet_ntop(entry->r->sa_af, &d, dst, sizeof(dst)), ntohs(entry->r->dport),
//                    ntohs(entry->r->seq), ntohs(entry->r->ack_seq));
//     }

//     DEBUG_CTRL("%s\tpid:%d, comm:%s %s %d %s", 
//                tls_event_type_str[event->type][0], event->pid, event->comm, 
//                tls_event_type_str[event->type][1], event->len, event->len == 1 ? "byte" : "bytes");

//     DEBUG_CTRL("%s\n", buf);
// }

static void dp_ebpf_tls_sniff_rx_cb(void *ctx, int cpu, void *data, __u32 data_size)
{
    uint8_t *dpi_rcv_pkt_ptr;
    io_ctx_t context;
    dp_context_t *dp_ctx = (dp_context_t *)ctx;
    struct probe_tls_sniff_event_t *event = data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint32_t buf_size = 0;
    uint32_t total_len = 0;

    memset(&context, 0, sizeof(io_ctx_t));
    context.dp_ctx = ctx;
    context.tick = dp_ctx->ebpf_ctx.last_tick;
    context.stats_slot = g_stats_slot;
    context.ebpf_tls = true;
    mac_cpy(context.ep_mac.ether_addr_octet, dp_ctx->ep_mac.ether_addr_octet);

    dpi_rcv_pkt_ptr = g_ebpf_tls_rx_buf;

    // setup eth header
    eth = (struct ethhdr *)dpi_rcv_pkt_ptr;
    memset(eth, 0, sizeof(struct ethhdr));
    eth->h_proto = htons(ETH_P_IP);

    // setup ip header
    iph = (struct iphdr *)(dpi_rcv_pkt_ptr + sizeof(struct ethhdr));
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) >> 2;
    iph->protocol = IPPROTO_TCP;

    // setup tcp header
    tcph = (struct tcphdr *)(dpi_rcv_pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
    memset(tcph, 0, sizeof(struct tcphdr));

    dp_ebpf_tcp_pkt_entry_t *entry = rcu_map_lookup(&g_ebpf_tcp_pkt_map, &event->pid);
    if (entry) {
        context.ebpf_tls_pid = entry->r->pid;
        if (event->type == SSL_READ) {
            context.ebpf_tls_ingress = true;
            iph->saddr = entry->r->daddr_v4;
            iph->daddr = entry->r->saddr_v4;
            tcph->th_sport = entry->r->dport;
            tcph->th_dport = entry->r->lport;
        } else if (event->type == SSL_WRITE) {
            context.ebpf_tls_ingress = false;
            iph->saddr = entry->r->saddr_v4;
            iph->daddr = entry->r->daddr_v4;
            tcph->th_sport = entry->r->lport;
            tcph->th_dport = entry->r->dport;
        }
        tcph->th_seq = entry->r->seq;
        tcph->th_ack = entry->r->ack_seq;
    }

    if (event->len <= MAX_BUF_SIZE) {
        buf_size = event->len;
    } else {
        buf_size = MAX_BUF_SIZE;
    }
    if (buf_size < event->len) {
        DEBUG_CTRL("Warning!! %d bytes lost.\n", event->len - buf_size);
    }

    // debug print 
    // print_tls_plain_text(event);

    total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + buf_size;
    memcpy(&dpi_rcv_pkt_ptr[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)], event->buf, buf_size);
    
    // DEBUG_CTRL("receive eBPF packet\n");
    dpi_recv_packet(&context, dpi_rcv_pkt_ptr, total_len);
    dp_ctx->ebpf_ctx.rx_accept++;
}

static void dp_ebpf_tls_sniff_rx_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
    dp_context_t *dp_ctx = (dp_context_t *)ctx;
    DEBUG_ERROR(DBG_CTRL, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
    dp_ctx->ebpf_ctx.rx_deny++;
}

static int dp_rx_ebpf_tls_sniff(dp_context_t *ctx, uint32_t tick)
{
    dp_ebpf_t *ebpf_ctx = &ctx->ebpf_ctx;
    ebpf_ctx->last_tick = tick;
    int err = perf_buffer__poll(ebpf_ctx->ebpf_tls_sniff_pb, PERF_POLL_TIMEOUT_MS);
    if (err < 0 && err != -EINTR) {
        DEBUG_ERROR(DBG_CTRL, "error polling TLS sniff perf buffer: %s\n", ctx->name);
        perf_buffer__free(ebpf_ctx->ebpf_tls_sniff_pb);
        tls_sniff_bpf__destroy(ebpf_ctx->ebpf_tls_sniff_obj);
    }

    return DP_RX_DONE;
}

static void dp_stats_ebpf_tls_sniff(dp_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->stats.rx += ctx->ebpf_ctx.rx_accept;
    ctx->ebpf_ctx.rx_accept = 0;
    ctx->stats.rx_drops += ctx->ebpf_ctx.rx_deny;
    ctx->ebpf_ctx.rx_deny = 0;
}

static int dp_ring_ebpf_tls_sniff(struct tls_sniff_bpf *obj, struct perf_buffer *pb, 
                                  dp_ebpf_t *ebpf_ctx)
{
    ebpf_ctx->ebpf_tls_sniff_pb = pb;
    ebpf_ctx->ebpf_tls_sniff_obj = obj;
    ebpf_ctx->rx = dp_rx_ebpf_tls_sniff;
    ebpf_ctx->stats = dp_stats_ebpf_tls_sniff;

    return 0;
}

int dp_open_ebpf_tls_sniff_handle(dp_context_t *ctx, const char *openssl_lib_path)
{
    struct tls_sniff_bpf *obj = NULL;
    struct perf_buffer *pb = NULL;
    int err;

    obj = tls_sniff_bpf__open_and_load();
    if (!obj) {
        DEBUG_ERROR(DBG_CTRL, "fail to open and load tls sniff bpf\n");
        goto cleanup;
    }

    if (attach_openssl(obj, openssl_lib_path) != 0) {
        goto cleanup;
    }
    DEBUG_CTRL("load and attach eBPF openssl lib:%s successfully\n", openssl_lib_path);

    pb = perf_buffer__new(bpf_map__fd(obj->maps.tls_events),
                          PERF_BUFFER_PAGES, dp_ebpf_tls_sniff_rx_cb, dp_ebpf_tls_sniff_rx_lost_event,
                          (void *)ctx, NULL);
    if (!pb) {
        DEBUG_ERROR(DBG_CTRL, "fail to create perf buffer\n");
        goto cleanup;
    }

    err = dp_ring_ebpf_tls_sniff(obj, pb, &ctx->ebpf_ctx);
    if (err < 0) {
        goto cleanup;
    }

    ctx->ebpf_ctx.ebpf_tls_sniff_pb = pb;
    ctx->ebpf_ctx.ebpf_tls_sniff_obj = obj;

    return 0;

cleanup:
    perf_buffer__free(pb);
    tls_sniff_bpf__destroy(obj);
    return -1;
}
