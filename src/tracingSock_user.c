#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include "tracingSock.h"
#include <bpf/libbpf.h>
#include <arpa/inet.h>

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

#define TASK_COMM_LEN 16

struct info
{
	char comm[TASK_COMM_LEN];
	__u32 pid;
	__u32 uid;
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

char *get_sk_addr4(__u8 addr[4])
{
	char ip4[16];
	int off = 0;
	for (int i = 0; i < 4; i++)
	{
		sprintf(ip4 + off, "%d", addr[i]); //每个数组元素循环转化为字符串
	}
	return ip4;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct info *i = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	time(&t);
	tm = localtime(&t);

	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (i->family == 2)
	{
		char src4[21];
		int offset = 0;
		for (int n = 0; n < 4; n++)
		{
			offset += sprintf(src4 + offset, "%d.", i->saddr[n]);
		}
		sprintf(src4 + offset - 1, ":%d", i->sport);
		char dst4[21];
		offset = 0;
		for (int n = 0; n < 4; n++)
		{
			offset += sprintf(dst4 + offset, "%d.", i->daddr[n]);
		}
		sprintf(dst4 + offset - 1, ":%d", i->dport);
		printf("%-9s %-16s %-6d    %-5d    %-4s          %-30s %-30s %s%s%s\n", ts, i->comm, i->pid, i->uid, i->protocol == 6 ? "TCP" : "UDP",
			   src4, dst4, i->protocol == 6 ?tcp_state[i->oldstate]:"", i->protocol == 6 ? "-->" : "", i->protocol == 6 ?tcp_state[i->newstate]:"");
	}
	else
	{
		char src6[30];
		int offset = 0;
		src6[0] = '[';
		for (int n = 0; n < 16; n++)
		{
			offset += sprintf(src6 + offset, "%x:", i->saddr_v6[n]);
		}
		sprintf(src6 + offset - 1, ":%d]", i->sport);
		char dst6[30];
		offset = 0;
		dst6[0] = '[';
		for (int n = 0; n < 16; n++)
		{
			offset += sprintf(dst6 + offset, "%x:", i->daddr_v6[n]);
		}
		sprintf(dst6 + offset - 1, ":%d]", i->dport);
		printf("%-9s %-16s %-6d    %-5d    %-4s          %-30s %-30s %s%s%s\n", ts, i->comm, i->pid, i->uid,i->protocol == 6 ? "TCP" : "UDP", src6, dst6,
			   i->protocol == 6 ?tcp_state[i->oldstate]:"", i->protocol == 6 ? "-->" : "", i->protocol == 6 ?tcp_state[i->newstate]:"");
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int map_fd = 0;
	int err;

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj))
	{
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj))
	{
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "sock_state");
	if (map_fd < 0)
	{
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "set_sock_state");
	if (!prog)
	{
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link))
	{
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	/* create ring buffer */
	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

	/* Process events */
	printf("  %s    %s              %s      %s   %s         %s                              %s                              %s\n", "TIME", "COMM","PID", "UID", "PROTOCOL", "SRC", "DST","STATE");
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return err < 0 ? -err : 0;
}
