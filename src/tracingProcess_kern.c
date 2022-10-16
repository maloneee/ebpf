#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} process SEC(".maps");

struct event {
	int pid;
	char comm[16];
	char filename[128];
};

SEC("tp/sched/sched_process_exec")
int p_start(struct trace_event_raw_sched_process_exec *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    struct event *e;
    e = bpf_ringbuf_reserve(&process, sizeof(*e), 0);
    if (!e)
		return 0;
    bpf_trace_printk("fname=%u\n", sizeof("fname_off=%d\n"), ctx->__data_loc_filename);
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_trace_printk("fname_off=%d\n", sizeof("fname_off=%d\n"), fname_off);
    e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm,sizeof(e->comm));
    bpf_printk("ctx: %u",  ctx);
    //bpf_trace_printk("size of ctx: %d\n", sizeof("size of ctx: %d\n"), sizeof(ctx));
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);
    //bpf_trace_printk("ctx=%d\n", sizeof("ctx=%d\n"), (void *)ctx + fname_off);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";