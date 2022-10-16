#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} process SEC(".maps");

#define TASK_COMM_LEN 16

struct info
{
    char comm[TASK_COMM_LEN];
    bool type;
    u32 pid;
    u32 uid;
    union
    {
        struct
        {
            char filename[128];
            char args[128];
            char envp[128];
        };
        u32 exit_code;
    };
};

SEC("tp/syscalls/sys_enter_execve")
int p_start(struct trace_event_raw_sys_enter *ctx)
{
    struct info *i;
    char *args_t;
    char *envp_t;
    i = bpf_ringbuf_reserve(&process, sizeof(struct info), 0);
    if (!i)
        return 0;
    bpf_core_read_user_str(i->filename, sizeof(i->filename), (char *)ctx->args[0]);
    bpf_core_read_user(&(args_t), sizeof(args_t), ctx->args[1]);
    bpf_core_read_user(&(envp_t), sizeof(envp_t), ctx->args[2]);
    bpf_core_read_user_str(i->args, sizeof(i->args), args_t);
    bpf_core_read_user_str(i->envp, sizeof(i->envp), envp_t);
    bpf_get_current_comm(i->comm, sizeof(i->comm));
    i->pid = bpf_get_current_pid_tgid() >> 32;
    i->uid = bpf_get_current_uid_gid() >> 32;
    i->type = 0;
    bpf_ringbuf_submit(i, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_exit")
int p_end(struct trace_event_raw_sys_enter *ctx)
{
    struct info *i;
    i = bpf_ringbuf_reserve(&process, sizeof(struct info), 0);
    if (!i)
        return 0;
    bpf_get_current_comm(i->comm, sizeof(i->comm));
    i->pid = bpf_get_current_pid_tgid() >> 32;
    i->uid = bpf_get_current_uid_gid() >> 32;
    i->exit_code = ctx->args[0];
    i->type = 1;
    bpf_ringbuf_submit(i, 0);
    return 0;
}
char _license[] SEC("license") = "GPL";