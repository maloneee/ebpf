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
    u16 family;
    __portpair skc_portpair;
    union
    {
        __addrpair skc_addrpair;
        struct
        {
            struct in6_addr skc_v6_daddr;
            struct in6_addr skc_v6_rcv_saddr;
        };
    };
    unsigned char skc_state;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct sock_common);
    __type(value, bool);
} temp SEC(".maps");

SEC("kprobe/udp_sendmsg")
int udp_sendmsg(struct pt_regs *ctx)
{
    struct info *i;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET)
    {   
        struct sock_common sc;
        bpf_core_read(&sc, sizeof(sc), &sk->__sk_common);
        bool value = bpf_map_lookup_elem(&temp,&sc);
        bool val = true;
        if (!value)
        {
            i = bpf_ringbuf_reserve(&udp_state, sizeof(struct info), 0);
            if (!i)
                return 0;
            bpf_get_current_comm(&i->comm, sizeof(i->comm));
            bpf_core_read(&i->skc_portpair, sizeof(i->skc_portpair), &sk->__sk_common.skc_portpair);
            bpf_core_read(&i->skc_addrpair, sizeof(i->skc_addrpair), &sk->__sk_common.skc_addrpair);
            bpf_core_read(&i->skc_state, sizeof(i->skc_state), &sk->__sk_common.skc_state);
            i->syscall = 1 >> 0;
            bpf_map_update_elem(&temp, &sc, &val, BPF_ANY);
            bpf_ringbuf_submit(i, 0);
            return 0;
        }
        else
            return 0;
    }
    else
        return 0;
}

SEC("kprobe/udp_recvmsg")
int udp_recvmsg(struct pt_regs *ctx)
{
    struct info *i;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET)
    {   
        struct sock_common sc;
        bpf_core_read(&sc, sizeof(sc), &sk->__sk_common);
        bool value = bpf_map_lookup_elem(&temp,&sc);
        bool val = true;
        if (!value)
        {
            i = bpf_ringbuf_reserve(&udp_state, sizeof(struct info), 0);
            if (!i)
                return 0;
            bpf_get_current_comm(&i->comm, sizeof(i->comm));
            bpf_core_read(&i->skc_portpair, sizeof(i->skc_portpair), &sk->__sk_common.skc_portpair);
            bpf_core_read(&i->skc_addrpair, sizeof(i->skc_addrpair), &sk->__sk_common.skc_addrpair);
            bpf_core_read(&i->skc_state, sizeof(i->skc_state), &sk->__sk_common.skc_state);
            i->syscall = 1 >> 1;
            bpf_map_update_elem(&temp, &sc, &val, BPF_ANY);
            bpf_ringbuf_submit(i, 0);
            return 0;
        }
        else
            return 0;
    }
    else
        return 0;
}

// SEC("kprobe/skb_consume_udp")
// int udp_recvmsg(struct pt_regs *ctx)
// {
// /*     struct info *i;
//     struct socket *sk = (struct socket *)PT_REGS_PARM1(ctx);
//     u16 type;
//     bpf_core_read(&type, sizeof(type), &sk->type);
//     if (type == 1)
//     {
//         i = bpf_ringbuf_reserve(&udp_state, sizeof(struct info), 0);
//         if (!i)
//             return 0;
//         bpf_get_current_comm(&i->comm, sizeof(i->comm));
//         // bpf_core_read(&i->skc_portpair, sizeof(i->skc_portpair), &sk->__sk_common.skc_portpair);
//         // bpf_core_read(&i->skc_addrpair, sizeof(i->skc_addrpair), &sk->__sk_common.skc_addrpair);
//         // bpf_core_read(&i->skc_state, sizeof(i->skc_state), &sk->__sk_common.skc_state);
//         // i->syscall = 1 >> 1;
//         // atomic64_t temp = BPF_CORE_READ(sk, __sk_common.skc_cookie);
//         bpf_printk("1");
//         bpf_ringbuf_submit(i, 0);
//         return 0;
//     }
//     else
//          */
//         bpf_printk("1");
//         return 0;
// }