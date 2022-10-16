#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

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
	bool type;
	uint32_t pid;
	uint32_t uid;
	union
	{
		struct
		{
			char filename[128];
			char args[128];
			char envp[128];
		};
		uint32_t exit_code;
	};
};

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
	if (!i->type)
	{
		printf("%-11s %-7s %-7d %-7d %-16s %-16s %-16s %s\n", ts, "EXEC", i->pid, i->uid, i->comm, i->args, i->envp, i->filename);
	}
	else
	{
		char exit_code[10];
		snprintf(exit_code, 10, "%d", i->exit_code);
		printf("%-11s %-7s %-7d %-7d %-16s %-16s %-16s %s\n", ts, "EXIT", i->pid, i->uid, i->comm, exit_code, "", "");
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int map_fd, j = 0;
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

	map_fd = bpf_object__find_map_fd_by_name(obj, "process");
	if (map_fd < 0)
	{
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj)
	{
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j]))
		{
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	/* create ring buffer */
	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

	/* Process events */
	printf("%-11s %-7s %-7s %-7s %-16s %-16s %-16s %s \n", "Time", "TYPE", "PID", "UID", "COMM", "ARGV/EXIT_CODE", "ENVP", "FILENAME");
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
	for (j--; j >= 0; j--)
		bpf_link__destroy(links[j]);
	bpf_object__close(obj);
	return err < 0 ? -err : 0;
}