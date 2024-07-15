#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf_common.h"

// #define MAX_ENTRIES 131072
#define MAX_ENTRIES 4096
// #define AF_INET  2
// #define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

/************************************
 * socket trace definition
 ************************************/
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tcp_socket_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, struct tcp_socket_info_t);
} tcp_socket_info_bufs SEC(".maps");

/************************************
 * socket trace handler
 ************************************/
static int handle_tcp_connect(struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct net *net_ns;
    task = (struct task_struct *)bpf_get_current_task();
    nsproxy = BPF_CORE_READ(task, nsproxy);
    net_ns = BPF_CORE_READ(nsproxy, net_ns);

    struct tcp_socket_info_t socket_info = {};
    socket_info.pid = pid;
    bpf_get_current_comm(&socket_info.comm, sizeof(socket_info.comm));
    socket_info.ns_id = BPF_CORE_READ(net_ns, ns.inum);

    bpf_map_update_elem(&tcp_socket_info_bufs, &sk, &socket_info, BPF_ANY);
    return 0;
}

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk, struct sk_buff *skb) {
    struct tcp_socket_info_t *socket_info;
    struct probe_tcp_socket_event_t socket_event = {};

    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

    socket_info = bpf_map_lookup_elem(&tcp_socket_info_bufs, &sk);
    if (!socket_info)
        return 0;

    socket_event.timestamp_ns = bpf_ktime_get_ns();
    socket_event.pid = socket_info->pid;
    __builtin_memcpy(&socket_event.comm, socket_info->comm, sizeof(socket_event.comm));
    socket_event.ns_id = socket_info->ns_id;
    socket_event.sa_af = BPF_CORE_READ(sk, __sk_common.skc_family);

    // Access the IP and TCP header from skb
    unsigned char *head = BPF_CORE_READ(skb, head);
    
    // L3
    u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr *iph = (struct iphdr *)(head + network_header);
    struct iphdr ip_header;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), iph);

    //L4
    u16 transport_header = BPF_CORE_READ(skb, transport_header);    
    struct tcphdr *tcph = (struct tcphdr *)(head + transport_header);
    struct tcphdr tcp_header;
    bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), tcph);

    // The *skb contains the packet from the remote side. This is because TCP_SYN_SENT
    // indicates that the local machine has already sent a SYN packet to initiate the 
    // connection and is now waiting for a SYN-ACK response from the remote side.
    // Therefore, the IP addresses and ports will be reversed.
    socket_event.saddr_v4 = ip_header.daddr;
    socket_event.daddr_v4 = ip_header.saddr;
    socket_event.lport = tcp_header.dest;
    socket_event.dport = tcp_header.source;
    socket_event.seq = tcp_header.seq;
    socket_event.ack_seq = tcp_header.ack_seq;

    bpf_perf_event_output(ctx, &tcp_socket_events, BPF_F_CURRENT_CPU, &socket_event, sizeof(struct probe_tcp_socket_event_t));

    bpf_map_delete_elem(&tcp_socket_info_bufs, &sk);
    return 0;
}

/************************************
 * socket trace probe section
 ************************************/
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
	return handle_tcp_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk, struct sk_buff *skb) {
	return handle_tcp_rcv_state_process(ctx, sk, skb);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk) {
	return handle_tcp_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk, struct sk_buff *skb) {
	return handle_tcp_rcv_state_process(ctx, sk, skb);
}
