#ifndef __EBPF_COMMON_H__
#define __EBPF_COMMON_H__

#define MAX_BUF_SIZE 1024 * 8
#define TASK_COMM_LEN 16

/************************************
 * TLS trace definition
 ************************************/
typedef enum {
    SSL_READ  = 0,
    SSL_WRITE = 1
} tls_event_type;

struct probe_tls_sniff_event_t {
    tls_event_type type;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 len;
    char comm[TASK_COMM_LEN];
    char buf[MAX_BUF_SIZE];
};

struct openssl_buf_t {
    const char* buf;
};

/************************************
 * TCP socket trace definition
 ************************************/
struct probe_tcp_socket_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u32 ns_id;
    sa_family_t sa_af;
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    __u16 lport;
    __u16 dport;
    __u32 seq;
    __u32 ack_seq;
};

struct tcp_socket_info_t {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u32 ns_id;
};

#endif /* __EBPF_COMMON_H__ */
