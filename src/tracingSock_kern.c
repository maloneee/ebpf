#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} sock_state SEC(".maps");

#define TASK_COMM_LEN 16

struct info
{
    char comm[TASK_COMM_LEN];
    u32 pid;
    u32 uid;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tp/sock/inet_sock_set_state")
int set_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{   
    if(ctx->protocol == 6||ctx->protocol==17){
    struct info *i;
    i = bpf_ringbuf_reserve(&sock_state, sizeof(struct info), 0);
    if (!i)
        return 0;
    i->pid = bpf_get_current_pid_tgid()>>(32);
    i->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&i->comm, sizeof(i->comm));
    bpf_core_read(i->saddr, sizeof(i->saddr), &ctx->saddr);
    bpf_core_read(i->daddr, sizeof(i->daddr), &ctx->daddr);
    bpf_core_read(i->saddr_v6, sizeof(i->saddr_v6), &ctx->saddr_v6);
    bpf_core_read(i->daddr_v6, sizeof(i->daddr_v6), &ctx->daddr_v6);
    bpf_core_read(&i->sport, sizeof(i->sport), &ctx->sport);
    i->dport = ctx->dport;
    bpf_core_read(&i->family, sizeof(i->family), &ctx->family);
    bpf_core_read(&i->protocol, sizeof(i->protocol), &ctx->protocol);
    bpf_core_read(&i->oldstate, sizeof(i->oldstate), &ctx->oldstate);
    bpf_core_read(&i->newstate, sizeof(i->newstate), &ctx->newstate);
    bpf_ringbuf_submit(i, 0);
    return 0;
    }else return 0;
}

char _license[] SEC("license") = "GPL";
