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
	const void *skaddr;
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

char * getSK_state(int stat,__u16 protocol){
	char state[] = "";   
	if(!(protocol ^ (__u16)6)){
		memcpy(state, tcp_state[stat], sizeof(tcp_state[stat]));
	}
	return state;
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
    char str6[INET6_ADDRSTRLEN];
    char str4[INET_ADDRSTRLEN];
    char sport[6]={0};
    char dport[6]={0};
    snprintf(sport ,6, "%d", i->sport);
    snprintf(dport ,6, "%d", i->dport);
    char state[30];
	strcpy(state,strcat(strcat(getSK_state(i->newstate,i->protocol)," --> "),getSK_state(i->oldstate,i->protocol)));
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%s %s %s %u %u %u %u %d %d\n",i->comm,i->daddr,i->saddr,i->dport,i->sport,i->protocol,i->family,i->newstate,i->oldstate) ;
   // i->family == 10 ? strcat(strcat(inet_ntop(AF_INET6, i->saddr_v6, str6, INET6_ADDRSTRLEN),":"),sport) : "UNKNOWN" );
	/*printf("%-11s %-5d %-5d %-7s %-7s %-16s %-16s %s \n", ts,i->pid, i->uid, i->comm, i->protocol == 6 ? "TCP" : i->protocol == 17 ? "UDP" : "OTHERS", 
    i->family == 2 ? strcat(strcat(inet_ntop(AF_INET, i->saddr, str4, INET_ADDRSTRLEN),":"),sport) : 
    i->family == 10 ? strcat(strcat(inet_ntop(AF_INET6, i->saddr_v6, str6, INET6_ADDRSTRLEN),":"),sport) : "UNKNOWN",
    i->family == 2 ? strcat(strcat(inet_ntop(AF_INET, i->daddr, str4, INET_ADDRSTRLEN),":"),dport) : 
    i->family == 10 ? strcat(strcat(inet_ntop(AF_INET6, i->daddr_v6, str6, INET6_ADDRSTRLEN),":"),dport) : "UNKNOWN",
    state );*/

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
	printf("%-11s %-5s %-5s %-7s %-5s %-16s %-16s %s\n", "TIME", "PID", "UID", "COMM","PROTOCOL","SRC","DST","STATE");
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

