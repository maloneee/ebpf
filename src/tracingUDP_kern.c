#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} udp_state SEC(".maps");

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct info
{
    char comm[TASK_COMM_LEN];
    u8 syscall;
    u32 pid;
    u32 uid;
    union
    {
        struct sockaddr_in saddr4;
        struct sockaddr_in6 saddr6;
    };
};

SEC("kprobe/__sys_sendto")
int sendto(struct pt_regs *ctx)
{
    struct info *i;
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
    u16 family = BPF_CORE_READ_USER(addr, sa_family);
    if (family == AF_INET)
    {
        i = bpf_ringbuf_reserve(&udp_state, sizeof(struct info), 0);
        if (!i)
            return 0;
        i->pid = bpf_get_current_pid_tgid() >> (32);
        i->uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&i->comm, sizeof(i->comm));
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        bpf_core_read_user(&i->saddr4.sin_family, sizeof(u16), &addr4->sin_family);
        bpf_core_read_user(&i->saddr4.sin_port, sizeof(i->saddr4.sin_port), &addr4->sin_port);
        bpf_core_read_user(&i->saddr4.sin_addr, sizeof(i->saddr4.sin_addr), &addr4->sin_addr);
        i->syscall = 1 >> 0;
        bpf_ringbuf_submit(i, 0);
        return 0;
    }
    else
        return 0;
}

SEC("kprobe/__sys_recvfrom")
int recvfrom(struct pt_regs *ctx)
{
    struct info *i;
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
    u16 family = BPF_CORE_READ_USER(addr, sa_family);
    if (family == AF_INET)
    {
        i = bpf_ringbuf_reserve(&udp_state, sizeof(struct info), 0);
        if (!i)
            return 0;
        i->pid = bpf_get_current_pid_tgid() >> (32);
        i->uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&i->comm, sizeof(i->comm));
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        bpf_core_read_user(&i->saddr4.sin_family, sizeof(u16), &addr4->sin_family);
        bpf_core_read_user(&i->saddr4.sin_port, sizeof(i->saddr4.sin_port), &addr4->sin_port);
        bpf_core_read_user(&i->saddr4.sin_addr, sizeof(i->saddr4.sin_addr), &addr4->sin_addr);
        i->syscall = 1 >> 1;
        bpf_ringbuf_submit(i, 0);
        return 0;
    }
    else
        return 0;
}
