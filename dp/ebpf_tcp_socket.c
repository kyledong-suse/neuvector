#include "main.h"
#include "apis.h"
#include "debug.h"
#include "utils/helper.h"
#include "dpi/dpi_module.h"

#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "tcp_socket.skel.h"
#include "ebpf_common.h"

rcu_map_t g_ebpf_netns_map;
rcu_map_t g_ebpf_tcp_pkt_map;
uint16_t g_ebpf_tcp_pkt_count;

/*************************************
 * TCP socket storage section
 *************************************/
static int dp_ebpf_netns_match(struct cds_lfht_node *ht_node, const void *key)
{
    dp_ebpf_netns_entry_t *e = STRUCT_OF(ht_node, dp_ebpf_netns_entry_t, node);
    const uint32_t *k = key;

    return (e->r->inum == *k);
}

static uint32_t dp_ebpf_netns_hash(const void *key)
{
    const uint32_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(uint32_t));
}

void dp_ebpf_netns_init()
{
    rcu_map_init(&g_ebpf_netns_map, 64, offsetof(dp_ebpf_netns_entry_t, node), 
                 dp_ebpf_netns_match, dp_ebpf_netns_hash);
}

static int dp_ebpf_tcp_pkt_match(struct cds_lfht_node *ht_node, const void *key)
{
    dp_ebpf_tcp_pkt_entry_t *e = STRUCT_OF(ht_node, dp_ebpf_tcp_pkt_entry_t, node);
    const uint32_t *k = key;

    return (e->r->pid == *k);
}

static uint32_t dp_ebpf_tcp_pkt_hash(const void *key)
{
    const uint32_t *k = key;
    return sdbm_hash((uint8_t *)k, sizeof(uint32_t));
}

static void dp_ebpf_tcp_pkt_release(timer_entry_t *entry)
{
    dp_ebpf_tcp_pkt_entry_t *e = STRUCT_OF(entry, dp_ebpf_tcp_pkt_entry_t, ts_entry);
    rcu_map_del(&g_ebpf_tcp_pkt_map, e);
    free(e);
}

void dp_ebpf_tcp_pkt_init()
{
    rcu_map_init(&g_ebpf_tcp_pkt_map, 64, offsetof(dp_ebpf_tcp_pkt_entry_t, node), 
                 dp_ebpf_tcp_pkt_match, dp_ebpf_tcp_pkt_hash);
}

/*************************************
 * TCP socket eBPF helper section
 *************************************/
static void add_dp_ebpf_tcp_pkt_v4_entry(uint32_t pid, sa_family_t sa_af, uint32_t saddr, uint32_t daddr,
                                         uint16_t lport, uint16_t dport, uint32_t seq, uint32_t ack_seq,
                                         char *comm)
{
    dp_ebpf_tcp_pkt_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        DEBUG_ERROR(DBG_CTRL, "OOM!!!\n");
        return;
    }

    dp_ebpf_tcp_pkt_record_t *r = calloc(1, sizeof(*r));
    if (!r) {
        DEBUG_ERROR(DBG_CTRL, "OOM!!!\n");
        free(entry);
        return;
    }
    r->pid = pid;
    memcpy(r->comm, comm, sizeof(r->comm));
    r->sa_af = sa_af;
    r->saddr_v4 = saddr;
    r->daddr_v4 = daddr;
    r->lport = lport;
    r->dport = dport;
    r->seq = seq;
    r->ack_seq = ack_seq;

    entry->r = r;
    rcu_map_add(&g_ebpf_tcp_pkt_map, entry, &pid);

    timer_wheel_entry_init(&entry->ts_entry);
    timer_wheel_entry_start(&th_timer, &entry->ts_entry,
                            dp_ebpf_tcp_pkt_release, EBPF_TCP_PKT_RECORD_TIMEOUT, th_snap.tick);
}

static void update_dp_ebpf_tcp_pkt_v4_entry(dp_ebpf_tcp_pkt_entry_t *entry, sa_family_t sa_af,
                                            uint32_t saddr, uint32_t daddr, uint16_t lport, uint16_t dport,
                                            uint32_t seq, uint32_t ack_seq, char *comm)
{
    if (strncmp(entry->r->comm, comm, TASK_COMM_LEN) != 0) {
        memcpy(entry->r->comm, comm, sizeof(entry->r->comm));
    }
    if (entry->r->sa_af != sa_af) {
        entry->r->sa_af = sa_af;
    }
    if (entry->r->saddr_v4 != saddr) {
        entry->r->saddr_v4 = saddr;
    }
    if (entry->r->daddr_v4 != daddr) {
        entry->r->daddr_v4 = daddr;
    }
    if (entry->r->lport != lport) {
        entry->r->lport = lport;
    }
    if (entry->r->dport != dport) {
        entry->r->dport = dport;
    }
    if (entry->r->seq != seq) {
        entry->r->seq = seq;
    }
    if (entry->r->ack_seq != ack_seq) {
        entry->r->ack_seq = ack_seq;
    }

    timer_wheel_entry_refresh(&th_timer, &entry->ts_entry, th_snap.tick);
}

/*************************************
 * TCP socket eBPF section
 *************************************/
static int load_and_attach_tcp_socket(struct tcp_socket_bpf *skel) {
    int err;

    bpf_program__set_attach_target(skel->progs.fentry_tcp_v4_connect, 0, "tcp_v4_connect");
    bpf_program__set_attach_target(skel->progs.fentry_tcp_rcv_state_process, 0, "tcp_rcv_state_process");
    bpf_program__set_autoload(skel->progs.tcp_v4_connect, false);
    bpf_program__set_autoload(skel->progs.tcp_rcv_state_process, false);
    
    err = tcp_socket_bpf__load(skel);
    if (err) {
        DEBUG_ERROR(DBG_CTRL, "fail to load TCP socket BPF\n");
        return -1;
    }

    err = tcp_socket_bpf__attach(skel);
    if (err) {
        DEBUG_ERROR(DBG_CTRL, "fail to attach TCP socket BPF\n");
        return -1;
    }

    return 0;
}

static void dp_ebpf_tcp_socket_rx_cb(void *ctx, int cpu, void *data, __u32 data_size)
{
    dp_context_t *ebpf_ctx = (dp_context_t *)ctx;
    struct probe_tcp_socket_event_t *event = data;

    rcu_read_lock();
    dp_ebpf_netns_entry_t *netns_entry = rcu_map_lookup(&g_ebpf_netns_map, &event->ns_id);
    if (netns_entry) {
        dp_ebpf_tcp_pkt_entry_t *tcp_pkt_entry = rcu_map_lookup(&g_ebpf_tcp_pkt_map, &event->pid);
        // currently only support IPv4
        if (event->sa_af == AF_INET) {
            if (!tcp_pkt_entry) {
                add_dp_ebpf_tcp_pkt_v4_entry(event->pid, event->sa_af, event->saddr_v4, event->daddr_v4,
                                             event->lport, event->dport, event->seq, event->ack_seq,
                                             event->comm);
            } else {
                update_dp_ebpf_tcp_pkt_v4_entry(tcp_pkt_entry, event->sa_af, event->saddr_v4, event->daddr_v4,
                                                event->lport, event->dport, event->seq, event->ack_seq,
                                                event->comm);
            }
        } else {
            DEBUG_ERROR(DBG_CTRL, "Unknown/Unsupported IP address format %d\n", event->sa_af);
        }
    }
    rcu_read_unlock();

    ebpf_ctx->ebpf_ctx.rx_accept++;
}

static void dp_ebpf_tcp_socket_rx_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
    dp_context_t *ebpf_ctx = (dp_context_t *)ctx;
    DEBUG_ERROR(DBG_CTRL, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
    ebpf_ctx->ebpf_ctx.rx_deny++;
}

static int dp_rx_ebpf_tcp_socket_sniff(dp_context_t *ctx, uint32_t tick)
{
	dp_ebpf_t *ebpf_ctx = &ctx->ebpf_ctx;
    ebpf_ctx->last_tick = tick;
    int err = perf_buffer__poll(ebpf_ctx->ebpf_tcp_socket_pb, PERF_POLL_TIMEOUT_MS);
    if (err < 0 && err != -EINTR) {
        DEBUG_ERROR(DBG_CTRL, "error polling TCP socket perf buffer: %s\n", ctx->name);
        perf_buffer__free(ebpf_ctx->ebpf_tcp_socket_pb);
        tcp_socket_bpf__destroy(ebpf_ctx->ebpf_tcp_socket_obj);
    }

    return DP_RX_DONE;
}

static void dp_stats_ebpf_tcp_socket_sniff(dp_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->stats.rx += ctx->ebpf_ctx.rx_accept;
    ctx->ebpf_ctx.rx_accept = 0;
    ctx->stats.rx_drops += ctx->ebpf_ctx.rx_deny;
    ctx->ebpf_ctx.rx_deny = 0;
}

static int dp_ring_ebpf_tcp_socket(struct tcp_socket_bpf *obj, struct perf_buffer *pb, 
                                   dp_ebpf_t *ebpf_ctx)
{
    ebpf_ctx->ebpf_tcp_socket_pb = pb;
    ebpf_ctx->ebpf_tcp_socket_obj = obj;
    ebpf_ctx->rx = dp_rx_ebpf_tcp_socket_sniff;
    ebpf_ctx->stats = dp_stats_ebpf_tcp_socket_sniff;

    return 0;
}

int dp_open_ebpf_tcp_socket_handle(dp_context_t *ctx)
{
    struct tcp_socket_bpf *obj = NULL;
    struct perf_buffer *pb = NULL;
    int err;

    obj = tcp_socket_bpf__open();
    if (!obj) {
        DEBUG_ERROR(DBG_CTRL, "fail to open TCP socket BPF\n");
        goto cleanup;
    }

    if(load_and_attach_tcp_socket(obj) != 0) {
        goto cleanup;
    }
    DEBUG_CTRL("load and attach eBPF tcp_socket successfully\n");

    pb = perf_buffer__new(bpf_map__fd(obj->maps.tcp_socket_events),
                          PERF_BUFFER_PAGES, dp_ebpf_tcp_socket_rx_cb, dp_ebpf_tcp_socket_rx_lost_event,
                          (void *)ctx, NULL);
    if (!pb) {
        DEBUG_ERROR(DBG_CTRL, "fail to create TCP socket perf buffer\n");
        goto cleanup;
    }

    err = dp_ring_ebpf_tcp_socket(obj, pb, &ctx->ebpf_ctx);
    if (err < 0) {
        goto cleanup;
    }

    ctx->ebpf_ctx.ebpf_tcp_socket_pb = pb;
    ctx->ebpf_ctx.ebpf_tcp_socket_obj = obj;

    return 0;

cleanup:
    perf_buffer__free(pb);
    tcp_socket_bpf__destroy(obj);
    return -1;
}
