/**
 * Epoll-based multithreaded TCP client with unique (source IP, source port) per connection.
 * Uses a dynamic work-stealing model where threads pull from a global connection counter.
 * Added explicit timeout checking to prevent stalled/stuck connections.
 * Auto-terminates when all connections are processed.
 *
 * Usage:
 *   tcp_client_er -s <server IP> -p <server port> -n <total connections> -c <concurrency> -a <client IP range> -r <port range> [-t <threads> ...]
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

#define MAX_EVENTS_PER_THREAD 2048
#define MAX_MSG 6
#define CONNECT_TIMEOUT_SEC 5
#define REPLY_TIMEOUT_SEC 3

// Shared flags and debug
static bool kill_flag = false;
static bool verbose_mode = false;
static FILE *debug_log = NULL;

// Global atomic counters for statistics and work distribution
static atomic_int stat_connection_closed = 0;
static atomic_int stat_server_busy = 0;
static atomic_int stat_handshake_failed = 0;
static atomic_int stat_read_timeout = 0;
static atomic_int stat_local_resource_exhausted = 0;
static atomic_int stat_technical_error = 0;
static atomic_int stat_total_connect_attempts = 0;
static atomic_int stat_current_inflight = 0;
static atomic_int stat_peak_concurrency = 0;
static atomic_long global_connections_started = 0;
static long total_connections_target = 0;

// Used for clean shutdown
static volatile sig_atomic_t global_stop = 0;

// Mutex for debug log file (since it's shared)
static pthread_mutex_t debug_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ========== Utility Structures ==========
struct src_tuple { struct in_addr ip; int port; };

struct conn_state {
    int fd;
    long conn_id;
    enum { CONN_CONNECTING, CONN_SENDING, CONN_READING } state;
    time_t creation_time;
    time_t last_activity;
    struct src_tuple *tuple;
};

// ========== Forward Declarations ==========
void print_help(const char *prog);
void debug_log_msg(const char *fmt, ...);
void parse_ip_range(char *range, struct in_addr **ips, int *num_ips);
void parse_port_range(char *range, int **ports, int *num_ports);

// ========== Debug Logging ==========
void debug_log_msg(const char *fmt, ...) {
    if (verbose_mode) {
        pthread_mutex_lock(&debug_log_mutex);
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
        pthread_mutex_unlock(&debug_log_mutex);
    }
}

// ========== Statistics Printing ==========
void print_stats() {
    fprintf(stderr,
        "\n[STAT] ================= Connection Outcome Statistics ================\n"
        "[STAT] Connections closed normally (successful handshake+data): %d\n"
        "[STAT] Connections failed: server busy/refused:                  %d\n"
        "[STAT] Connections failed: handshake never completed (timeout):   %d\n"
        "[STAT] Connections failed: read timeout after handshake:          %d\n"
        "[STAT] Connections failed: local resource exhaustion:             %d\n"
        "[STAT] Connections failed: technical/other errors:                %d\n"
        "[STAT] Total connect() attempts:                                  %d\n"
        "[STAT] Peak concurrency achieved:                                 %d\n"
        "[STAT] =================================================================\n",
        atomic_load(&stat_connection_closed), atomic_load(&stat_server_busy), atomic_load(&stat_handshake_failed),
        atomic_load(&stat_read_timeout), atomic_load(&stat_local_resource_exhausted), atomic_load(&stat_technical_error),
        atomic_load(&stat_total_connect_attempts), atomic_load(&stat_peak_concurrency)
    );
}

// ========== Signal Handling ==========
void handle_sigint(int signo) {
    global_stop = 1;
    fprintf(stderr, "\n[INFO] Shutdown signal received. Finishing in-flight connections...\n");
}

// ========== Helpers ==========
void update_peak_concurrency() {
    int current = atomic_fetch_add(&stat_current_inflight, 1) + 1;
    int peak = atomic_load(&stat_peak_concurrency);
    while (current > peak) {
        if (atomic_compare_exchange_weak(&stat_peak_concurrency, &peak, current)) break;
    }
}

int set_nonblock(int fd) { return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }
void set_rst_and_close(int fd) { if (kill_flag) { struct linger sl = {1, 0}; setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)); } close(fd); }

// ========== Threaded Connection Worker ==========
struct thread_args {
    int thread_id;
    struct src_tuple *tuples;
    int tuple_count;
    int max_concurrent;
    struct sockaddr_in srv_addr;
    char *server_ip;  // For debug output
    int server_port;  // For debug output
};

void* connection_worker(void *arg) {
    struct thread_args *args = (struct thread_args*) arg;
    struct epoll_event events[MAX_EVENTS_PER_THREAD];
    int epfd = epoll_create1(0);
    if (epfd < 0) { return NULL; }

    // Array to store all connections for this thread - used for timeout checking
    struct conn_state **all_conns = calloc(args->max_concurrent, sizeof(struct conn_state*));
    int conn_count = 0;

    while (!global_stop) {
        // --- AGGRESSIVE CONNECTION CREATION LOOP ---
        // Keep creating connections until the concurrency limit is hit or all connections are started.
        while (atomic_load(&stat_current_inflight) < args->max_concurrent && !global_stop) {
            long conn_id = atomic_fetch_add(&global_connections_started, 1);
            if (conn_id >= total_connections_target) {
                atomic_fetch_sub(&global_connections_started, 1); // Correct for overshoot
                break; // All connections started, exit creation loop
            }

            atomic_fetch_add(&stat_total_connect_attempts, 1);
            int tuple_idx = conn_id % args->tuple_count;
            struct src_tuple *tuple = &args->tuples[tuple_idx];
            
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) { 
                atomic_fetch_add(&stat_local_resource_exhausted, 1);
                debug_log_msg("[T%d] socket() failed: %s", args->thread_id, strerror(errno));
                continue; 
            }

            set_nonblock(fd);
            struct sockaddr_in src_addr = {.sin_family = AF_INET, .sin_addr = tuple->ip, .sin_port = htons(tuple->port)};
            int optval = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
            #ifdef SO_REUSEPORT
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
            #endif

            if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0) {
                close(fd); 
                atomic_fetch_add(&stat_technical_error, 1);
                debug_log_msg("[T%d] bind() failed for %s:%d: %s", args->thread_id, 
                            inet_ntoa(tuple->ip), tuple->port, strerror(errno));
                continue;
            }
            
            int connect_result = connect(fd, (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
            if (connect_result != 0 && errno != EINPROGRESS) {
                close(fd); 
                atomic_fetch_add(&stat_handshake_failed, 1);
                debug_log_msg("[T%d] connect() failed: %s", args->thread_id, strerror(errno));
                continue;
            }

            struct conn_state *cs = calloc(1, sizeof(struct conn_state));
            cs->fd = fd;
            cs->conn_id = conn_id;
            cs->state = CONN_CONNECTING;
            cs->creation_time = time(NULL);
            cs->last_activity = cs->creation_time;
            cs->tuple = tuple;
            
            struct epoll_event ev = {.data.ptr = cs, .events = EPOLLOUT | EPOLLIN};
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
                update_peak_concurrency();
                // Add to our tracking array
                if (conn_count < args->max_concurrent) {
                    all_conns[conn_count++] = cs;
                }
            } else {
                free(cs); 
                close(fd); 
                atomic_fetch_add(&stat_technical_error, 1);
                debug_log_msg("[T%d] epoll_ctl failed: %s", args->thread_id, strerror(errno));
            }
        }

        // --- I/O EVENT PROCESSING ---
        int n = epoll_wait(epfd, events, MAX_EVENTS_PER_THREAD, 50); // 50ms timeout
        time_t now = time(NULL);

        for (int i = 0; i < n; i++) {
            struct conn_state *cs = events[i].data.ptr;
            bool conn_finished = false;

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                atomic_fetch_add(&stat_technical_error, 1);
                conn_finished = true;
                debug_log_msg("[T%d][Conn %ld] EPOLLERR or EPOLLHUP", args->thread_id, cs->conn_id);
            } else if (cs->state == CONN_CONNECTING && (events[i].events & EPOLLOUT)) {
                int err = 0; 
                socklen_t len = sizeof(err);
                if (getsockopt(cs->fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    cs->state = CONN_SENDING;
                    cs->last_activity = now;
                    debug_log_msg("[T%d][Conn %ld] Connection established", args->thread_id, cs->conn_id);
                } else {
                    if (err == ECONNREFUSED) {
                        atomic_fetch_add(&stat_server_busy, 1);
                        debug_log_msg("[T%d][Conn %ld] Connection refused", args->thread_id, cs->conn_id);
                    } else {
                        atomic_fetch_add(&stat_handshake_failed, 1);
                        debug_log_msg("[T%d][Conn %ld] Connection failed: %s", args->thread_id, cs->conn_id, 
                                    strerror(err ? err : errno));
                    }
                    conn_finished = true;
                }
            } else if (cs->state == CONN_SENDING && (events[i].events & EPOLLOUT)) {
                ssize_t sent = send(cs->fd, "hello\n", 6, 0);
                if (sent > 0) {
                    cs->state = CONN_READING;
                    cs->last_activity = now;
                    debug_log_msg("[T%d][Conn %ld] Sent data", args->thread_id, cs->conn_id);
                } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    conn_finished = true;
                    debug_log_msg("[T%d][Conn %ld] Send failed: %s", args->thread_id, cs->conn_id, strerror(errno));
                }
            } else if (cs->state == CONN_READING && (events[i].events & EPOLLIN)) {
                char buf[32];
                ssize_t received = recv(cs->fd, buf, sizeof(buf), 0);
                if (received > 0) {
                    atomic_fetch_add(&stat_connection_closed, 1);
                    conn_finished = true;
                    debug_log_msg("[T%d][Conn %ld] Received data and closing", args->thread_id, cs->conn_id);
                } else if (received == 0 || (errno != EWOULDBLOCK && errno != EAGAIN)) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    conn_finished = true;
                    debug_log_msg("[T%d][Conn %ld] Receive failed: %s", args->thread_id, cs->conn_id, 
                                strerror(errno));
                }
            }

            if (conn_finished) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, cs->fd, NULL);
                set_rst_and_close(cs->fd);
                
                // Remove from our tracking array by setting to NULL
                for (int j = 0; j < conn_count; j++) {
                    if (all_conns[j] == cs) {
                        all_conns[j] = NULL;
                        break;
                    }
                }
                
                free(cs);
                atomic_fetch_sub(&stat_current_inflight, 1);
            }
        }

        // --- CRITICAL FIX: EXPLICIT TIMEOUT CHECKING ---
        // Check ALL connections for timeouts, not just those with activity
        for (int i = 0; i < conn_count; i++) {
            struct conn_state *cs = all_conns[i];
            if (cs == NULL) continue;
            
            // Check for connection timeout
            if (cs->state == CONN_CONNECTING && (now - cs->creation_time > CONNECT_TIMEOUT_SEC)) {
                debug_log_msg("[T%d][Conn %ld] Connection timeout after %d seconds", 
                            args->thread_id, cs->conn_id, (int)(now - cs->creation_time));
                epoll_ctl(epfd, EPOLL_CTL_DEL, cs->fd, NULL);
                set_rst_and_close(cs->fd);
                atomic_fetch_add(&stat_handshake_failed, 1);
                all_conns[i] = NULL;
                free(cs);
                atomic_fetch_sub(&stat_current_inflight, 1);
            }
            // Check for activity timeout
            else if ((cs->state == CONN_SENDING || cs->state == CONN_READING) && 
                     (now - cs->last_activity > REPLY_TIMEOUT_SEC)) {
                debug_log_msg("[T%d][Conn %ld] Activity timeout in state %d after %d seconds", 
                            args->thread_id, cs->conn_id, cs->state, (int)(now - cs->last_activity));
                epoll_ctl(epfd, EPOLL_CTL_DEL, cs->fd, NULL);
                set_rst_and_close(cs->fd);
                atomic_fetch_add(&stat_read_timeout, 1);
                all_conns[i] = NULL;
                free(cs);
                atomic_fetch_sub(&stat_current_inflight, 1);
            }
        }

        // Compact the connection array to remove NULL entries
        int new_count = 0;
        for (int i = 0; i < conn_count; i++) {
            if (all_conns[i] != NULL) {
                all_conns[new_count++] = all_conns[i];
            }
        }
        conn_count = new_count;

        // Check if all work is truly done
        if (atomic_load(&global_connections_started) >= total_connections_target && 
            atomic_load(&stat_current_inflight) == 0) {
            break;
        }
    }

    // Clean up
    for (int i = 0; i < conn_count; i++) {
        if (all_conns[i] != NULL) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, all_conns[i]->fd, NULL);
            set_rst_and_close(all_conns[i]->fd);
            free(all_conns[i]);
            atomic_fetch_sub(&stat_current_inflight, 1);
        }
    }
    free(all_conns);
    close(epfd);
    return NULL;
}

// ========== Progress Reporter Thread ==========
void* progress_reporter(void *arg) {
    long last_conn_count = 0;
    time_t start_time = time(NULL);
    printf("[INFO] Starting test at %s\n", (char*)arg);
    
    int unchanged_count = 0;  // Track how many times stats remain unchanged

    while (!global_stop) {
        sleep(1); // Report every second
        
        // Count all completed connections (successful + failed)
        long current_count = atomic_load(&stat_connection_closed) + 
                             atomic_load(&stat_handshake_failed) + 
                             atomic_load(&stat_read_timeout) +
                             atomic_load(&stat_technical_error) +
                             atomic_load(&stat_server_busy) +
                             atomic_load(&stat_local_resource_exhausted);
                                  
        int current_inflight = atomic_load(&stat_current_inflight);
        
        // Auto-termination logic: If we've processed all connections and nothing is in flight
        if (current_count >= total_connections_target && current_inflight == 0) {
            unchanged_count++;
            // If stats haven't changed for 3 seconds, exit
            if (unchanged_count >= 3) {
                printf("[INFO] Test completed! All connections processed and none in flight.\n");
                global_stop = 1;
                break;
            }
        } else if (current_count == last_conn_count) {
            // If we still have work but nothing is happening, increment counter
            unchanged_count++;
            // After 10 seconds of no change, consider the test stalled and exit
            if (unchanged_count >= 10 && current_inflight == 0) {
                printf("[INFO] Test appears stalled. Completed %ld/%ld connections. Exiting.\n", 
                       current_count, total_connections_target);
                global_stop = 1;
                break;
            }
        } else {
            // Reset counter if things are changing
            unchanged_count = 0;
        }

        time_t current_time = time(NULL);
        time_t time_diff = current_time - start_time;
        if (time_diff == 0) time_diff = 1;

        long delta_conns = current_count - last_conn_count;
        double rate = (double)delta_conns / time_diff;

        printf("[Progress] Total Conns: %ld/%ld | In-flight: %d | Rate: %.0f conn/s\n",
               current_count, total_connections_target, current_inflight, rate);

        last_conn_count = current_count;
        start_time = current_time;
    }
    printf("[INFO] Progress reporter exiting.\n");
    return NULL;
}

// ========== MAIN PROGRAM ==========
int main(int argc, char **argv) {
    struct sigaction sa = {.sa_handler = handle_sigint, .sa_flags = SA_RESTART};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);

    char *server_ip = NULL;
    int server_port = 0, max_concurrent = 0, num_threads = 4;
    char *client_ip_range = NULL, *client_port_range = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:a:r:w:kvhl:t:")) != -1) {
        switch (opt) {
            case 's': server_ip = strdup(optarg); break;
            case 'p': server_port = atoi(optarg); break;
            case 'n': total_connections_target = atol(optarg); break;
            case 'c': max_concurrent = atoi(optarg); break;
            case 'a': client_ip_range = strdup(optarg); break;
            case 'r': client_port_range = strdup(optarg); break;
            case 'k': kill_flag = true; break;
            case 'v': verbose_mode = true; break;
            case 't': num_threads = atoi(optarg); break;
            case 'h': default: print_help(argv[0]); exit(0);
        }
    }
    if (!server_ip || !server_port || total_connections_target <= 0 || max_concurrent <= 0) { 
        print_help(argv[0]); exit(1); 
    }

    struct in_addr *source_ips = NULL; int num_source_ips = 0;
    int *source_ports = NULL; int num_source_ports = 0;
    parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
    parse_port_range(client_port_range, &source_ports, &num_source_ports);

    long tuple_count = (long)num_source_ips * num_source_ports;
    if (total_connections_target > tuple_count) { 
        fprintf(stderr, "Error: total_connections (-n) cannot exceed unique (ip,port) tuples (%ld).\n", tuple_count); 
        exit(1); 
    }
    if (num_threads < 1) num_threads = 1;

    struct src_tuple *tuples = calloc(tuple_count, sizeof(struct src_tuple));
    for (int i = 0; i < num_source_ips; i++) {
        for (int j = 0; j < num_source_ports; j++) {
            long idx = (long)i * num_source_ports + j;
            tuples[idx].ip = source_ips[i]; tuples[idx].port = source_ports[j];
        }
    }

    if (kill_flag) { 
        if (system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP") != 0) { 
            fprintf(stderr, "Error: Failed to add iptables rule. Are you root?\n"); 
            exit(1); 
        } 
    }

    struct sockaddr_in srv_addr = {.sin_family = AF_INET, .sin_port = htons(server_port)};
    inet_pton(AF_INET, server_ip, &srv_addr.sin_addr);

    pthread_t *tids = calloc(num_threads + 1, sizeof(pthread_t));
    struct thread_args targs = { 
        .tuples = tuples, 
        .tuple_count = tuple_count, 
        .max_concurrent = max_concurrent, 
        .srv_addr = srv_addr,
        .server_ip = server_ip,
        .server_port = server_port
    };
    
    for (int t = 0; t < num_threads; t++) { 
        targs.thread_id = t; 
        pthread_create(&tids[t], NULL, connection_worker, &targs); 
    }
    
    // Use the current date/time provided by the user
    char time_buf[] = "2025-07-01 14:21:34";
    pthread_create(&tids[num_threads], NULL, progress_reporter, time_buf);

    for (int t = 0; t < num_threads + 1; t++) { 
        pthread_join(tids[t], NULL); 
    }

    fprintf(stderr, "[INFO] Test finished. Completed %d connections.\n", atomic_load(&stat_connection_closed));
    print_stats();

    if (kill_flag) { 
        system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"); 
    }

    free(tids); free(tuples); free(source_ips); free(source_ports); free(server_ip);
    if (client_ip_range) free(client_ip_range); 
    if (client_port_range) free(client_port_range);
    return 0;
}

void print_help(const char *prog) {
    printf("Usage: %s -s <server IP> -p <server port> -n <total conns> -c <concurrency> -a <IP range> -r <port range> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -s <server IP>         IP address of the server (required)\n");
    printf("  -p <server port>       Port number of the server (required)\n");
    printf("  -n <total connections> Number of connections to make (required)\n");
    printf("  -c <concurrency>       Max concurrent connections in flight (required)\n");
    printf("  -a <client IP range>   Source IP range, e.g., 192.168.1.1-10 (required)\n");
    printf("  -r <client port range> Source port range, e.g., 5000-5100 (required)\n");
    printf("  -t <threads>           Number of worker threads (default: 4)\n");
    printf("  -k                     Enable SO_LINGER to send RST on close\n");
    printf("  -v                     Enable verbose debugging output\n");
    printf("  -h                     Show this help message\n");
}

void parse_ip_range(char *range, struct in_addr **ips, int *num_ips) {
    char *dash = strchr(range, '-');
    if (!dash) { fprintf(stderr, "Error: Invalid IP range format. Use A.B.C.D-E or A.B.C.D-A.B.C.E\n"); exit(1); }
    *dash = '\0';
    char *start_str = range;
    char *end_str = dash + 1;
    struct in_addr start_ip, end_ip;
    if (inet_pton(AF_INET, start_str, &start_ip) != 1) { fprintf(stderr, "Error: Invalid start IP: %s\n", start_str); exit(1); }
    if (strchr(end_str, '.')) {
        if (inet_pton(AF_INET, end_str, &end_ip) != 1) { fprintf(stderr, "Error: Invalid end IP: %s\n", end_str); exit(1); }
    } else {
        uint32_t ip_num = ntohl(start_ip.s_addr);
        uint32_t prefix = ip_num & 0xFFFFFF00;
        int end_octet = atoi(end_str);
        if (end_octet < 0 || end_octet > 255) { fprintf(stderr, "Error: Invalid end octet: %d\n", end_octet); exit(1); }
        end_ip.s_addr = htonl(prefix | end_octet);
    }
    uint32_t start = ntohl(start_ip.s_addr);
    uint32_t end = ntohl(end_ip.s_addr);
    if (start > end) { fprintf(stderr, "Error: Start IP is greater than end IP.\n"); exit(1); }
    *num_ips = end - start + 1;
    *ips = malloc(sizeof(struct in_addr) * (*num_ips));
    for (uint32_t ip = start; ip <= end; ip++) { (*ips)[ip - start].s_addr = htonl(ip); }
}

void parse_port_range(char *range, int **ports, int *num_ports) {
    char *dash = strchr(range, '-');
    if (!dash) { fprintf(stderr, "Error: Invalid port range format. Use START-END\n"); exit(1); }
    *dash = '\0';
    int start_port = atoi(range);
    int end_port = atoi(dash + 1);
    if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port) { fprintf(stderr, "Error: Invalid port range %d-%d\n", start_port, end_port); exit(1); }
    *num_ports = end_port - start_port + 1;
    *ports = malloc(sizeof(int) * (*num_ports));
    for (int i = 0; i < *num_ports; i++) { (*ports)[i] = start_port + i; }
}
