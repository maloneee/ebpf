#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
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
#define AF_INET 2
#define AF_INET6 10

struct info
{
    char comm[TASK_COMM_LEN];
    __u8 syscall;
    __u16 family;
    __be16 skc_dport;
    __u16 skc_num;
    union
    {

        struct
        {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
        struct
        {
            struct in6_addr skc_v6_daddr;
            struct in6_addr skc_v6_rcv_saddr;
        };
    };
    unsigned char skc_state;
};

// char *get_addr(__u16 family, void *addr)
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
    char src4[21];
    int offset = 0;
    for (int n = 0; n < 4; n++)
    {
        offset += sprintf(src4 + offset, "%d.", i->skc_daddr >> (n * 8) & 0xff);
    }
    sprintf(src4 + offset - 1, ":%d", i->skc_num);
    char dst4[21];
    offset = 0;
    for (int n = 0; n < 4; n++)
    {
        offset += sprintf(dst4 + offset, "%d.", i->skc_rcv_saddr >> (n * 8) & 0xff);
    }
    sprintf(dst4 + offset - 1, ":%d", ntohs(i->skc_dport));
    printf("%s %s %s %s %d\n", ts, i->comm, src4, dst4, i->skc_state);
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

    map_fd = bpf_object__find_map_fd_by_name(obj, "udp_state");
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
    // printf("  %s    %s              %s      %s   %s         %s                              %s                              %s\n", "TIME", "COMM", "PID", "UID", "PROTOCOL", "SRC", "DST", "STATE");
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
    for (int i = 0; i < j; i++)
    {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    return err < 0 ? -err : 0;
}