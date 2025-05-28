/**
 * Epoll-based multithreaded UDP client with unique (source IP, source port) per "connection".
 * Each thread handles a partition of the source IP range.
 * All threads update shared atomic counters for statistics.
 * Each UDP "session" is one send/recv (with a timeout for reply).
 *
 * Usage:
 *   udp_client_multi -s <server IP> -p <server port> -n <total requests> -c <concurrency> -a <client IP range> -r <port range> [-t <threads> ...]
 */

#define _GNU_SOURCE // For pthread_setname_np
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <pthread.h>

#define MAX_EVENTS 1024
#define MAX_MSG 6
#define REPLY_TIMEOUT_SEC 2

// Shared flags and debug
static bool debug_mode = false;
static bool kill_flag = false;
static FILE *debug_log = NULL;

// Atomic counters for statistics (shared between all threads)
static atomic_int stat_local_resource_exhausted = 0;
static atomic_int stat_no_reply = 0;
static atomic_int stat_technical_error = 0;
static atomic_int stat_success = 0;
static atomic_int stat_total_attempts = 0;

// Used for clean shutdown
static volatile sig_atomic_t global_stop = 0;

// Mutex for debug log file (since it's shared)
static pthread_mutex_t debug_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ========== Debug and Logging ==========

void open_debug_log(const char *filename) {
    debug_log = fopen(filename, "a");
    if (!debug_log) {
        fprintf(stderr, "Failed to open debug log file %s: %s\n", filename, strerror(errno));
        exit(2);
    }
    setvbuf(debug_log, NULL, _IOLBF, 0); // Line-buffered
}

void close_debug_log() {
    if (debug_log) {
        fclose(debug_log);
        debug_log = NULL;
    }
}

void debug_print(const char *fmt, ...) {
    if (debug_mode && debug_log) {
        pthread_mutex_lock(&debug_log_mutex);
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_log, fmt, args);
        fprintf(debug_log, "\n");
        va_end(args);
        pthread_mutex_unlock(&debug_log_mutex);
    }
}

void fatal_print(const char *fmt, ...) {
    if (debug_log) {
        pthread_mutex_lock(&debug_log_mutex);
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_log, fmt, args);
        fprintf(debug_log, "\n");
        va_end(args);
        pthread_mutex_unlock(&debug_log_mutex);
    } else {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
    }
}

// ========== Statistics Printing ==========

void print_stats() {
    fprintf(stderr,
        "\n[STAT] ================= UDP Statistics ================\n"
        "[STAT] Requests successful:                  %d\n"
        "[STAT] Requests with no reply (timeout):     %d\n"
        "[STAT] Requests failed: local resource:      %d\n"
        "[STAT] Requests failed: technical/other:     %d\n"
        "[STAT] Total requests sent:                  %d\n"
        "[STAT] =================================================\n",
        stat_success, stat_no_reply, stat_local_resource_exhausted, stat_technical_error, stat_total_attempts
    );
    if (debug_log) {
        pthread_mutex_lock(&debug_log_mutex);
        fprintf(debug_log,
            "\n[STAT] ================= UDP Statistics ================\n"
            "[STAT] Requests successful:                  %d\n"
            "[STAT] Requests with no reply (timeout):     %d\n"
            "[STAT] Requests failed: local resource:      %d\n"
            "[STAT] Requests failed: technical/other:     %d\n"
            "[STAT] Total requests sent:                  %d\n"
            "[STAT] =================================================\n",
            stat_success, stat_no_reply, stat_local_resource_exhausted, stat_technical_error, stat_total_attempts
        );
        fflush(debug_log);
        pthread_mutex_unlock(&debug_log_mutex);
    }
}

// ========== Signal Handling ==========

void handle_sigint(int signo) {
    global_stop = 1; // Set global stop flag
    print_stats();
    if (debug_log) fflush(debug_log);
    _exit(130); // Exit code 130 for Ctrl-C
}

// ========== Utility Structures ==========

struct src_tuple {
    struct in_addr ip;
    int port;
};

struct udp_state {
    int fd;
    int id;
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    char readbuf[MAX_MSG];
    time_t send_time;
    bool replied;
    struct src_tuple *tuple;
};

// ========== Helpers ==========

void print_help(const char *prog) {
    printf("Usage:\n");
    printf("  %s -s <server IP> -p <server port> -n <total requests> -c <concurrency> -a <client IP range> -r <port range> [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -s <server IP>         IP address of the server\n");
    printf("  -p <server port>       Port number of the server\n");
    printf("  -n <total requests>    Number of requests to make\n");
    printf("  -c <concurrency>       Max concurrent requests in flight (window size)\n");
    printf("  -a <client IP range>   Source IP range (e.g., 192.168.1.1-10)\n");
    printf("  -r <client port range> Source port range (e.g., 5000-5100)\n");
    printf("  -w <wait ms>           Wait time (ms) after each batch of requests\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -l <debug log file>    Write debug output to this file (default: ./udp_client_debug.log)\n");
    printf("  -t <threads>           Number of threads (default: 4)\n");
    printf("  -h                     Show this help message\n");
    exit(0);
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void parse_ip_range(char *range, struct in_addr **ips, int *num_ips) {
    char *dash = strchr(range, '-');
    if (!dash) {
        fatal_print("Invalid IP range format");
        exit(1);
    }
    *dash = '\0';
    char *start_str = range;
    char *end_str = dash + 1;
    struct in_addr start_ip, end_ip;
    if (inet_pton(AF_INET, start_str, &start_ip) != 1) {
        fatal_print("Invalid start IP: %s", start_str);
        exit(1);
    }
    if (strchr(end_str, '.')) {
        if (inet_pton(AF_INET, end_str, &end_ip) != 1) {
            fatal_print("Invalid end IP: %s", end_str);
            exit(1);
        }
    } else {
        uint32_t ip_num = ntohl(start_ip.s_addr);
        uint32_t prefix = ip_num & 0xFFFFFF00;
        int end_octet = atoi(end_str);
        if (end_octet < 0 || end_octet > 255) {
            fatal_print("Invalid end octet: %d", end_octet);
            exit(1);
        }
        end_ip.s_addr = htonl(prefix | end_octet);
    }
    uint32_t start = ntohl(start_ip.s_addr);
    uint32_t end = ntohl(end_ip.s_addr);
    if (start > end) {
        fatal_print("Start IP greater than end IP");
        exit(1);
    }
    *num_ips = end - start + 1;
    *ips = malloc(sizeof(struct in_addr) * (*num_ips));
    for (uint32_t ip = start; ip <= end; ip++) {
        (*ips)[ip - start].s_addr = htonl(ip);
    }
    debug_print("[DEBUG] Parsed IP range: %s - %s (%d addrs)", start_str, end_str, *num_ips);
}

void parse_port_range(char *range, int **ports, int *num_ports) {
    char *dash = strchr(range, '-');
    if (!dash) {
        fatal_print("Invalid port range format");
        exit(1);
    }
    *dash = '\0';
    int start_port = atoi(range);
    int end_port = atoi(dash + 1);
    if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port) {
        fatal_print("Invalid port range %d-%d", start_port, end_port);
        exit(1);
    }
    *num_ports = end_port - start_port + 1;
    *ports = malloc(sizeof(int) * (*num_ports));
    for (int i = 0; i < *num_ports; i++) {
        (*ports)[i] = start_port + i;
    }
    debug_print("[DEBUG] Parsed port range: %d-%d (%d ports)", start_port, end_port, *num_ports);
}

// ========== Threaded UDP Worker ==========

struct thread_args {
    int thread_id;
    struct src_tuple *tuples;
    int tuple_count;
    int total_requests;
    int max_concurrent;
    double wait_time_ms;
    struct sockaddr_in srv_addr;
    char *server_ip;
    int server_port;
};

void* udp_worker(void *arg) {
    struct thread_args *args = (struct thread_args*) arg;
    int started = 0, finished = 0;
    int tuple_last_used = 0;
    char send_msg[] = "hello\n";
    int progress_step = args->total_requests / 10;
    if (progress_step == 0) progress_step = 1;
    int progress = 0;
    struct epoll_event events[MAX_EVENTS];

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        fatal_print("epoll_create1 failed: %s", strerror(errno));
        pthread_exit(NULL);
    }

    while (started < args->total_requests && !global_stop) {
        int batch = (args->total_requests - started > args->max_concurrent) ? args->max_concurrent : (args->total_requests - started);
        struct udp_state **states = calloc(batch, sizeof(struct udp_state*));
        int inflight = 0;

        for (int i = 0; i < batch && !global_stop; i++) {
            int t_idx = tuple_last_used;
            tuple_last_used = (tuple_last_used + 1) % args->tuple_count;
            struct src_tuple *tuple = &args->tuples[t_idx];

            atomic_fetch_add(&stat_total_attempts, 1);

            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                if (errno == EMFILE || errno == ENFILE) {
                    atomic_fetch_add(&stat_local_resource_exhausted, 1);
                    fatal_print("[STAT][T%d] Local resource exhaustion: socket() failed with %s", args->thread_id, strerror(errno));
                } else {
                    atomic_fetch_add(&stat_technical_error, 1);
                    fatal_print("[STAT][T%d] Technical error: socket() failed with %s", args->thread_id, strerror(errno));
                }
                continue;
            }
            if (set_nonblock(fd) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                fatal_print("[STAT][T%d] Technical error: set_nonblock failed: %s", args->thread_id, strerror(errno));
                close(fd);
                continue;
            }

            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            src_addr.sin_addr = tuple->ip;
            src_addr.sin_port = htons(tuple->port);

            int optval = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
#ifdef SO_REUSEPORT
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
#endif

            if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                fatal_print("[STAT][T%d] Technical error: bind() failed for %s:%d: %s", args->thread_id, inet_ntoa(src_addr.sin_addr), tuple->port, strerror(errno));
                close(fd);
                continue;
            }

            ssize_t wr = sendto(fd, send_msg, MAX_MSG, 0,
                               (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
            if (wr != MAX_MSG) {
                atomic_fetch_add(&stat_technical_error, 1);
                fatal_print("[STAT][T%d] Technical error: sendto() error: %s", args->thread_id, strerror(errno));
                close(fd);
                continue;
            }
            debug_print("[DEBUG][T%d][Req %d] Sent UDP packet src %s:%d -> dst %s:%d",
                args->thread_id, started + i,
                inet_ntoa(src_addr.sin_addr), tuple->port,
                args->server_ip, args->server_port);

            struct udp_state *us = calloc(1, sizeof(struct udp_state));
            us->fd = fd;
            us->id = started + i;
            us->src_addr = src_addr;
            us->dst_addr = args->srv_addr;
            us->send_time = time(NULL);
            us->replied = false;
            us->tuple = tuple;

            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.ptr = us;
            ev.events = EPOLLIN;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                fatal_print("[STAT][T%d] Technical error: epoll_ctl ADD failed: %s", args->thread_id, strerror(errno));
                close(fd); free(us); continue;
            }
            states[inflight] = us;
            inflight++;
        }

        // Event loop for batch
        int batch_finished = 0;
        while (batch_finished < inflight && !global_stop) {
            int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
            time_t now = time(NULL);

            // Timeout checks (reply)
            for (int i = 0; i < inflight; ++i) {
                struct udp_state *us = states[i];
                if (!us || us->replied) continue;
                if ((now - us->send_time) > REPLY_TIMEOUT_SEC) {
                    atomic_fetch_add(&stat_no_reply, 1);
                    debug_print("[DEBUG][T%d][Req %d] No reply (timeout)", args->thread_id, us->id);
                    close(us->fd); free(us); states[i] = NULL; batch_finished++;
                }
            }

            if (n < 0) {
                if (errno == EINTR) continue;
                atomic_fetch_add(&stat_technical_error, 1);
                fatal_print("[STAT][T%d] Technical error: epoll_wait failed: %s", args->thread_id, strerror(errno));
                break;
            }
            for (int i = 0; i < n; ++i) {
                struct udp_state *us = events[i].data.ptr;
                if (!us || us->replied) continue;
                ssize_t rd = recv(us->fd, us->readbuf, MAX_MSG, 0);
                if (rd <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    atomic_fetch_add(&stat_technical_error, 1);
                    fatal_print("[STAT][T%d] Technical error: recv() error: %s", args->thread_id, strerror(errno));
                    close(us->fd); free(us); us = NULL; batch_finished++; continue;
                }
                us->replied = true;
                atomic_fetch_add(&stat_success, 1);
                debug_print("[DEBUG][T%d][Req %d] Got reply", args->thread_id, us->id);
                close(us->fd); free(us); states[i] = NULL; batch_finished++;
                progress++;
                if (progress_step && progress % progress_step == 0) {
                    printf("[T%d] Progress: %d/%d (%d%%)\n", args->thread_id, progress, args->total_requests, (progress * 100) / args->total_requests);
                    fflush(stdout);
                }
            }
        }
        free(states);
        if (args->wait_time_ms > 0 && started + batch < args->total_requests) {
            debug_print("[DEBUG][T%d] Sleeping %.2f ms after batch", args->thread_id, args->wait_time_ms);
            usleep((useconds_t)(args->wait_time_ms * 1000));
        }
        started += batch;
    }
    debug_print("[SUMMARY][T%d] Completed %d requests", args->thread_id, args->total_requests);
    close(epfd);
    pthread_exit(NULL);
}

// ========== MAIN PROGRAM ==========

int main(int argc, char **argv) {
    // Set up SIGINT/SIGTERM handler for stats on Ctrl-C
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Command line args
    char *server_ip = NULL;
    int server_port = 0;
    int total_requests = 0;
    int max_concurrent = 0;
    char *client_ip_range = NULL;
    char *client_port_range = NULL;
    double wait_time_ms = 0;
    char *debug_log_file = NULL;
    int num_threads = 4; // Default

    // Parse options
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:a:r:w:Dl:t:h")) != -1) {
        switch (opt) {
            case 's': server_ip = strdup(optarg); break;
            case 'p': server_port = atoi(optarg); break;
            case 'n': total_requests = atoi(optarg); break;
            case 'c': max_concurrent = atoi(optarg); break;
            case 'a': client_ip_range = strdup(optarg); break;
            case 'r': client_port_range = strdup(optarg); break;
            case 'w': wait_time_ms = atof(optarg); break;
            case 'D': debug_mode = true; break;
            case 'l': debug_log_file = strdup(optarg); break;
            case 't': num_threads = atoi(optarg); break;
            case 'h': print_help(argv[0]);
            default:  print_help(argv[0]);
        }
    }
    if (!server_ip || !server_port || total_requests <= 0 || max_concurrent <= 0 || !client_ip_range || !client_port_range) {
        print_help(argv[0]);
    }
    if (!debug_log_file) {
        debug_log_file = strdup("./udp_client_debug.log");
    }
    open_debug_log(debug_log_file);

    // Parse IP and port ranges
    struct in_addr *source_ips = NULL;
    int num_source_ips = 0;
    int *source_ports = NULL;
    int num_source_ports = 0;
    parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
    parse_port_range(client_port_range, &source_ports, &num_source_ports);

    int tuple_count = num_source_ips * num_source_ports;
    if (total_requests > tuple_count) {
        fatal_print("total_requests (-n) cannot exceed unique (ip,port) tuples (%d).", tuple_count);
        exit(1);
    }
    if (max_concurrent > tuple_count) {
        fatal_print("max_concurrent (-c) cannot exceed unique (ip,port) tuples (%d).", tuple_count);
        exit(1);
    }
    if (num_threads < 1) num_threads = 1;
    if (num_threads > num_source_ips) num_threads = num_source_ips; // Can't have more threads than IPs

    debug_print("[DEBUG] Connecting to server %s:%d, total requests: %d, concurrency: %d, tuples: %d, wait: %.2f ms, threads: %d",
                server_ip, server_port, total_requests, max_concurrent, tuple_count, wait_time_ms, num_threads);

    // Prepare socket address for server
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) != 1) {
        fatal_print("Invalid server IP: %s", server_ip);
        exit(1);
    }

    // Calculate per-thread assignments
    int *ips_per_thread = calloc(num_threads, sizeof(int));
    int rem = num_source_ips % num_threads;
    int base = num_source_ips / num_threads;
    for (int i = 0; i < num_threads; i++) {
        ips_per_thread[i] = base + (i < rem ? 1 : 0);
    }

    // Calculate per-thread request counts
    int *reqs_per_thread = calloc(num_threads, sizeof(int));
    rem = total_requests % num_threads;
    base = total_requests / num_threads;
    for (int i = 0; i < num_threads; i++) {
        reqs_per_thread[i] = base + (i < rem ? 1 : 0);
    }

    // Calculate per-thread concurrency
    int *max_inflight_per_thread = calloc(num_threads, sizeof(int));
    rem = max_concurrent % num_threads;
    base = max_concurrent / num_threads;
    for (int i = 0; i < num_threads; i++) {
        max_inflight_per_thread[i] = base + (i < rem ? 1 : 0);
    }

    // Launch threads
    pthread_t *tids = calloc(num_threads, sizeof(pthread_t));
    struct thread_args *targs = calloc(num_threads, sizeof(struct thread_args));
    int ip_start_idx = 0;
    for (int t = 0; t < num_threads; t++) {
        int ips_this = ips_per_thread[t];
        int tuples_this = ips_this * num_source_ports;
        struct src_tuple *tuples = calloc(tuples_this, sizeof(struct src_tuple));
        int idx = 0;
        for (int i = ip_start_idx; i < ip_start_idx + ips_this; i++) {
            for (int j = 0; j < num_source_ports; j++) {
                tuples[idx].ip = source_ips[i];
                tuples[idx].port = source_ports[j];
                idx++;
            }
        }
        ip_start_idx += ips_this;

        targs[t].thread_id = t;
        targs[t].tuples = tuples;
        targs[t].tuple_count = tuples_this;
        targs[t].total_requests = reqs_per_thread[t];
        targs[t].max_concurrent = max_inflight_per_thread[t];
        targs[t].wait_time_ms = wait_time_ms;
        targs[t].srv_addr = srv_addr;
        targs[t].server_ip = server_ip;
        targs[t].server_port = server_port;

        pthread_create(&tids[t], NULL, udp_worker, &targs[t]);
    }

    // Wait for all threads
    for (int t = 0; t < num_threads; t++) {
        pthread_join(tids[t], NULL);
        free(targs[t].tuples);
    }

    printf("Completed %d UDP requests\n", total_requests);
    print_stats();

    // Clean up
    free(ips_per_thread);
    free(reqs_per_thread);
    free(max_inflight_per_thread);
    free(tids);
    free(targs);
    free(source_ips);
    free(source_ports);
    free(server_ip);
    if (client_ip_range) free(client_ip_range);
    if (client_port_range) free(client_port_range);
    close_debug_log();
    if (debug_log_file) free(debug_log_file);
    return 0;
}
