#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf_common.h"

#define MAX_ENTRIES 4096

char LICENSE[] SEC("license") = "GPL";

/************************************
 * TLS trace definition
 ************************************/
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct probe_tls_sniff_event_t);
} probe_tls_event SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct openssl_buf_t);
} read_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct openssl_buf_t);
} write_bufs SEC(".maps");

static int handle_uretprobe_tls_event(struct pt_regs *ctx, tls_event_type tls_type, struct openssl_buf_t *openssl_buf) {
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    int len = PT_REGS_RC(ctx);
    if (len <= 0)
        return 0;

    struct probe_tls_sniff_event_t *tls_event = bpf_map_lookup_elem(&probe_tls_event, &zero);
    if (!tls_event)
        return 0;

    tls_event->timestamp_ns = bpf_ktime_get_ns();
    tls_event->pid = pid;
    tls_event->len = (u32)len;
    tls_event->type = tls_type;

    // const char fmt_str[] = "handle_uretprobe_tls_event fd is %d\n";
    // bpf_trace_printk(fmt_str, sizeof(fmt_str), tls_event->fd);

    bpf_get_current_comm(&tls_event->comm, sizeof(tls_event->comm));

    u32 copy_size = tls_event->len < MAX_BUF_SIZE ? tls_event->len : MAX_BUF_SIZE - 1;
    bpf_probe_read_user(&tls_event->buf, copy_size, openssl_buf->buf);

    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, tls_event, sizeof(struct probe_tls_sniff_event_t));

    return 0;
}

/************************************
 * BPF uprobe function section
 ************************************/
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct openssl_buf_t openssl_buf;
    __builtin_memset(&openssl_buf, 0, sizeof(openssl_buf));
    openssl_buf.buf = (const char*)buf;

    bpf_map_update_elem(&read_bufs, &tid, &openssl_buf, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct openssl_buf_t openssl_buf;
    __builtin_memset(&openssl_buf, 0, sizeof(openssl_buf));
    openssl_buf.buf = (const char*)buf;

    bpf_map_update_elem(&write_bufs, &tid, &openssl_buf, BPF_ANY);
    return 0;
}

/************************************
 * BPF uretprobe function section
 ************************************/
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_ret_ssl_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    struct openssl_buf_t *openssl_buf = bpf_map_lookup_elem(&read_bufs, &tid);
    if (openssl_buf == NULL)
        return 0;

    handle_uretprobe_tls_event(ctx, SSL_READ, openssl_buf);
    bpf_map_delete_elem(&read_bufs, &tid);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_ret_ssl_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    struct openssl_buf_t *openssl_buf = bpf_map_lookup_elem(&write_bufs, &tid);
    if (openssl_buf == NULL)
        return 0;

    handle_uretprobe_tls_event(ctx, SSL_WRITE, openssl_buf);
    bpf_map_delete_elem(&write_bufs, &tid);
    return 0;
}
