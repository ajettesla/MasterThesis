#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdatomic.h>
#include <time.h>
#include <getopt.h>
#include <stdarg.h>

#define MAX_RETRIES 3
#define BUF_SZ 128
#define MAX_EVENTS 100

const int TIMEOUTS[MAX_RETRIES] = {2, 4, 8}; // Retry timeouts in seconds

// Statistics
atomic_int stat_successful = 0;
atomic_int stat_failed = 0;
atomic_int stat_technical_error = 0;
atomic_int total_completed = 0; // Global counter for progress

// Debug logging and progress
int debug_mode = 0;
pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *debug_log = NULL;

struct src_tuple {
    char ip[INET_ADDRSTRLEN];
    int port;
};

struct thread_args {
    int thread_id;
    struct src_tuple *tuples;
    int tuple_count;
    int max_concurrent;
    int global_total_connections; // For progress reporting
    struct sockaddr_in srv_addr;
    char *server_ip;
    int server_port;
};

struct conn_state {
    int fd;
    struct src_tuple *tuple;
    int attempt;
    time_t deadline;
    enum { CS_INIT, CS_WAITING, CS_DONE, CS_ERROR } state;
    char recv_buf[BUF_SZ];
    int recv_len;
};

// Utility functions
void fatal_print(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    exit(1);
}

void debug_print(const char *fmt, ...) {
    if (!debug_mode) return;
    pthread_mutex_lock(&debug_mutex);
    va_list args;
    va_start(args, fmt);
    vfprintf(debug_log ? debug_log : stderr, fmt, args);
    va_end(args);
    fprintf(debug_log ? debug_log : stderr, "\n");
    if (debug_log) fflush(debug_log);
    pthread_mutex_unlock(&debug_mutex);
}

// Use inet_ntop instead of inet_ntoa for thread safety
void parse_ip_range(const char *range, char ***ips, int *count) {
    char *range_copy = strdup(range);
    char *start_str = strtok(range_copy, "-");
    char *end_str = strtok(NULL, "-");
    if (!start_str || !end_str) fatal_print("Invalid IP range format");

    struct in_addr start;
    if (inet_pton(AF_INET, start_str, &start) != 1) {
        fatal_print("Invalid start IP: %s", start_str);
    }

    struct in_addr end;
    if (strchr(end_str, '.') == NULL) {
        // End is last octet
        char full_end[INET_ADDRSTRLEN];
        char *dot1 = strchr(start_str, '.');
        char *dot2 = strchr(dot1 + 1, '.');
        char *dot3 = strchr(dot2 + 1, '.');
        if (!dot3) fatal_print("Invalid start IP format");
        snprintf(full_end, INET_ADDRSTRLEN, "%.*s.%s", (int)(dot3 - start_str), start_str, end_str);
        if (inet_pton(AF_INET, full_end, &end) != 1) {
            fatal_print("Invalid end IP: %s", full_end);
        }
    } else {
        if (inet_pton(AF_INET, end_str, &end) != 1) {
            fatal_print("Invalid end IP: %s", end_str);
        }
    }

    uint32_t start_num = ntohl(start.s_addr);
    uint32_t end_num = ntohl(end.s_addr);
    if (start_num > end_num) fatal_print("Start IP greater than end IP");

    *count = end_num - start_num + 1;
    *ips = malloc(*count * sizeof(char *));
    for (uint32_t i = 0; i < *count; i++) {
        struct in_addr addr;
        addr.s_addr = htonl(start_num + i);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
        (*ips)[i] = strdup(buf);
    }
    free(range_copy);
}

void parse_port_range(const char *range, int *start_port, int *end_port) {
    char *range_copy = strdup(range);
    char *start_str = strtok(range_copy, "-");
    char *end_str = strtok(NULL, "-");
    if (!start_str || !end_str) fatal_print("Invalid port range format");

    *start_port = atoi(start_str);
    *end_port = atoi(end_str);
    if (*start_port < 1 || *end_port > 65535 || *start_port > *end_port) {
        fatal_print("Invalid port range");
    }
    free(range_copy);
}

// Connection worker
void *connection_worker(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) fatal_print("Thread %d: epoll_create1 failed: %s", args->thread_id, strerror(errno));

    int batch_size = args->max_concurrent;
    int num_batches = (args->tuple_count + batch_size - 1) / batch_size;

    for (int b = 0; b < num_batches; b++) {
        int start = b * batch_size;
        int end = (b + 1) * batch_size;
        if (end > args->tuple_count) end = args->tuple_count;
        int active_conns = end - start;

        struct conn_state *conns = calloc(active_conns, sizeof(struct conn_state));
        struct epoll_event *events = calloc(active_conns, sizeof(struct epoll_event));

        // Initialize batch
        for (int i = 0; i < active_conns; i++) {
            struct conn_state *conn = &conns[i];
            conn->tuple = &args->tuples[start + i];
            conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (conn->fd < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                debug_print("Thread %d: Socket creation failed: %s", args->thread_id, strerror(errno));
                conn->state = CS_ERROR;
                continue;
            }

            struct sockaddr_in src_addr = {0};
            src_addr.sin_family = AF_INET;
            src_addr.sin_addr.s_addr = inet_addr(conn->tuple->ip);
            src_addr.sin_port = htons(conn->tuple->port);
            if (bind(conn->fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                debug_print("Thread %d: Bind failed for %s:%d: %s", args->thread_id, conn->tuple->ip, conn->tuple->port, strerror(errno));
                close(conn->fd);
                conn->fd = -1;
                conn->state = CS_ERROR;
                continue;
            }

            ssize_t sent = sendto(conn->fd, "hello\n", 6, 0, (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
            if (sent < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                debug_print("Thread %d: Send failed for %s:%d: %s", args->thread_id, conn->tuple->ip, conn->tuple->port, strerror(errno));
                close(conn->fd);
                conn->fd = -1;
                conn->state = CS_ERROR;
                continue;
            }
            debug_print("Thread %d: Sent hello from %s:%d", args->thread_id, conn->tuple->ip, conn->tuple->port);

            conn->attempt = 0;
            conn->deadline = time(NULL) + TIMEOUTS[conn->attempt];
            conn->state = CS_WAITING;

            struct epoll_event ev = {0};
            ev.events = EPOLLIN;
            ev.data.ptr = conn;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                debug_print("Thread %d: epoll_ctl failed: %s", args->thread_id, strerror(errno));
                close(conn->fd);
                conn->fd = -1;
                conn->state = CS_ERROR;
                continue;
            }
        }

        // Event loop for batch
        while (active_conns > 0) {
            time_t now = time(NULL);
            int timeout_ms = -1;
            for (int i = 0; i < end - start; i++) {
                if (conns[i].state == CS_WAITING) {
                    int remaining = (conns[i].deadline - now) * 1000;
                    if (remaining <= 0) {
                        timeout_ms = 0;
                        break;
                    }
                    if (timeout_ms == -1 || remaining < timeout_ms) timeout_ms = remaining;
                }
            }
            if (timeout_ms == -1) timeout_ms = 1000; // Default timeout

            int nfds;
            do {
                nfds = epoll_wait(epoll_fd, events, active_conns, timeout_ms);
            } while (nfds < 0 && errno == EINTR);
            if (nfds < 0) {
                debug_print("Thread %d: epoll_wait failed: %s", args->thread_id, strerror(errno));
                break;
            }

            // Handle incoming data
            for (int n = 0; n < nfds; n++) {
                struct conn_state *conn = (struct conn_state *)events[n].data.ptr;
                if (conn->state != CS_WAITING) continue;

                ssize_t received = recvfrom(conn->fd, conn->recv_buf, BUF_SZ - 1, 0, NULL, NULL);
                if (received < 0) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    debug_print("Thread %d: Recv failed for %s:%d: %s", args->thread_id, conn->tuple->ip, conn->tuple->port, strerror(errno));
                    conn->state = CS_ERROR;
                    continue;
                }
                conn->recv_buf[received] = '\0';
                debug_print("Thread %d: Received '%s' from %s:%d", args->thread_id, conn->recv_buf, conn->tuple->ip, conn->tuple->port);

                if (strcmp(conn->recv_buf, "hi\n") == 0) {
                    sendto(conn->fd, "got_hi\n", 7, 0, (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
                    debug_print("Thread %d: Sent got_hi from %s:%d", args->thread_id, conn->tuple->ip, conn->tuple->port);
                    conn->state = CS_DONE;
                    atomic_fetch_add(&stat_successful, 1);
                }
            }

            // Handle timeouts
            now = time(NULL);
            for (int i = 0; i < end - start; i++) {
                struct conn_state *conn = &conns[i];
                if (conn->state != CS_WAITING) continue;
                if (now >= conn->deadline) {
                    if (conn->attempt + 1 < MAX_RETRIES) {
                        conn->attempt++;
                        ssize_t sent = sendto(conn->fd, "hello\n", 6, 0, (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
                        if (sent < 0) {
                            atomic_fetch_add(&stat_technical_error, 1);
                            debug_print("Thread %d: Retry send failed for %s:%d: %s", args->thread_id, conn->tuple->ip, conn->tuple->port, strerror(errno));
                            conn->state = CS_ERROR;
                            continue;
                        }
                        debug_print("Thread %d: Retry %d sent hello from %s:%d", args->thread_id, conn->attempt, conn->tuple->ip, conn->tuple->port);
                        conn->deadline = now + TIMEOUTS[conn->attempt];
                    } else {
                        atomic_fetch_add(&stat_failed, 1);
                        debug_print("Thread %d: Failed after retries for %s:%d", args->thread_id, conn->tuple->ip, conn->tuple->port);
                        conn->state = CS_ERROR;
                    }
                }
            }

            // Clean up completed connections
            for (int i = 0; i < end - start; i++) {
                struct conn_state *conn = &conns[i];
                if ((conn->state == CS_DONE || conn->state == CS_ERROR) && conn->fd >= 0) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                    close(conn->fd);
                    conn->fd = -1;
                    active_conns--;
                    int completed = atomic_fetch_add(&total_completed, 1) + 1;
                    int step = args->global_total_connections / 10;
                    if (step > 0 && completed % step == 0) {
                        pthread_mutex_lock(&progress_mutex);
                        printf("Global Progress: %d/%d (%d%%)\n", completed, args->global_total_connections, (completed * 100) / args->global_total_connections);
                        fflush(stdout);
                        pthread_mutex_unlock(&progress_mutex);
                    }
                }
            }
        }

        free(conns);
        free(events);
    }

    close(epoll_fd);
    free(args->tuples);
    free(args);
    debug_print("Thread %d: Finished", args->thread_id);
    return NULL;
}

int main(int argc, char *argv[]) {
    char *server_ip = NULL;
    int server_port = 0;
    int total_connections = 0;
    int max_concurrent = 0;
    char *ip_range = NULL;
    char *port_range = NULL;
    int num_threads = 4;

    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:a:r:t:D")) != -1) {
        switch (opt) {
            case 's': server_ip = optarg; break;
            case 'p': server_port = atoi(optarg); break;
            case 'n': total_connections = atoi(optarg); break;
            case 'c': max_concurrent = atoi(optarg); break;
            case 'a': ip_range = optarg; break;
            case 'r': port_range = optarg; break;
            case 't': num_threads = atoi(optarg); break;
            case 'D': debug_mode = 1; break;
            default: fatal_print("Usage: %s -s server_ip -p server_port -n total_connections -c max_concurrent -a ip_range -r port_range [-t threads] [-D]", argv[0]);
        }
    }

    if (!server_ip || server_port <= 0 || total_connections <= 0 || max_concurrent <= 0 || !ip_range || !port_range) {
        fatal_print("Missing required arguments");
    }

    if (debug_mode) {
        debug_log = fopen("udp_heart_debug.log", "w");
        if (!debug_log) fatal_print("Failed to open debug log: %s", strerror(errno));
    }

    // Parse source tuples
    char **ips;
    int ip_count;
    parse_ip_range(ip_range, &ips, &ip_count);

    int start_port, end_port;
    parse_port_range(port_range, &start_port, &end_port);
    int port_count = end_port - start_port + 1;

    int tuple_count = ip_count * port_count;
    if (total_connections > tuple_count) {
        fatal_print("total_connections (-n) cannot exceed unique (ip,port) tuples (%d)", tuple_count);
    }

    struct src_tuple *all_tuples = malloc(tuple_count * sizeof(struct src_tuple));
    int t = 0;
    for (int i = 0; i < ip_count; i++) {
        for (int p = start_port; p <= end_port; p++) {
            snprintf(all_tuples[t].ip, INET_ADDRSTRLEN, "%s", ips[i]);
            all_tuples[t].port = p;
            t++;
        }
    }

    // Divide tuples among threads
    int base_tuples_per_thread = total_connections / num_threads;
    int remainder = total_connections % num_threads;

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) != 1) {
        fatal_print("Invalid server IP address");
    }

    int tuple_offset = 0;
    for (int i = 0; i < num_threads; i++) {
        int tuples_for_thread = base_tuples_per_thread + (i < remainder ? 1 : 0);
        if (tuples_for_thread == 0) break;

        struct thread_args *args = malloc(sizeof(struct thread_args));
        args->thread_id = i;
        args->tuples = malloc(tuples_for_thread * sizeof(struct src_tuple));
        memcpy(args->tuples, &all_tuples[tuple_offset], tuples_for_thread * sizeof(struct src_tuple));
        args->tuple_count = tuples_for_thread;
        args->max_concurrent = max_concurrent;
        args->global_total_connections = total_connections;
        args->srv_addr = srv_addr;
        args->server_ip = server_ip;
        args->server_port = server_port;

        pthread_create(&threads[i], NULL, connection_worker, args);
        tuple_offset += tuples_for_thread;
    }

    // Wait for threads (FIXED: always join all threads)
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Print statistics
    printf("Successful connections: %d\n", atomic_load(&stat_successful));
    printf("Failed connections: %d\n", atomic_load(&stat_failed));
    printf("Technical errors: %d\n", atomic_load(&stat_technical_error));

    // Cleanup
    for (int i = 0; i < ip_count; i++) free(ips[i]);
    free(ips);
    free(all_tuples);
    free(threads);
    if (debug_mode) fclose(debug_log);

    return 0;
}
