/**
 * Epoll-based multithreaded TCP client with unique (source IP, source port) per connection.
 * Each thread handles a partition of the source IP range.
 * All threads update shared atomic counters for connection statistics.
 *
 * Usage:
 *   tcp_client_multi -s <server IP> -p <server port> -n <total connections> -c <concurrency> -a <client IP range> -r <port range> [-t <threads> ...]
 *
 * See the help message for more options.
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
#define CONNECT_TIMEOUT_SEC 5
#define REPLY_TIMEOUT_SEC 2
#define CONNECT_RETRIES 6
#define CONNECT_RETRY_DELAY_MS 100

// Shared flags and debug
static bool debug_mode = false;
static bool kill_flag = false;
static FILE *debug_log = NULL;

// Atomic counters for statistics (shared between all threads)
static atomic_int stat_local_resource_exhausted = 0;
static atomic_int stat_server_busy = 0;
static atomic_int stat_handshake_failed = 0;
static atomic_int stat_read_timeout = 0;
static atomic_int stat_connection_timeout = 0;
static atomic_int stat_connection_closed = 0;
static atomic_int stat_technical_error = 0;
static atomic_int stat_total_connect_attempts = 0;

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
        "\n[STAT] ================= Connection Outcome Statistics ================\n"
        "[STAT] Connections closed normally (successful handshake+data): %d\n"
        "[STAT] Connections failed: server busy/refused:                  %d\n"
        "[STAT] Connections failed: handshake never completed (timeout):   %d\n"
        "[STAT] Connections failed: read timeout after handshake:          %d\n"
        "[STAT] Connections failed: local resource exhaustion:             %d\n"
        "[STAT] Connections failed: technical/other errors:                %d\n"
        "[STAT] Total connect() attempts:                                  %d\n"
        "[STAT] =================================================================\n",
        stat_connection_closed, stat_server_busy, stat_handshake_failed,
        stat_read_timeout, stat_local_resource_exhausted, stat_technical_error, stat_total_connect_attempts
    );
    if (debug_log) {
        pthread_mutex_lock(&debug_log_mutex);
        fprintf(debug_log,
            "\n[STAT] ================= Connection Outcome Statistics ================\n"
            "[STAT] Connections closed normally (successful handshake+data): %d\n"
            "[STAT] Connections failed: server busy/refused:                  %d\n"
            "[STAT] Connections failed: handshake never completed (timeout):   %d\n"
            "[STAT] Connections failed: read timeout after handshake:          %d\n"
            "[STAT] Connections failed: local resource exhaustion:             %d\n"
            "[STAT] Connections failed: technical/other errors:                %d\n"
            "[STAT] Total connect() attempts:                                  %d\n"
            "[STAT] =================================================================\n",
            stat_connection_closed, stat_server_busy, stat_handshake_failed,
            stat_read_timeout, stat_local_resource_exhausted, stat_technical_error, stat_total_connect_attempts
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
    bool in_use; // NOT used in multithreaded version; each thread has its own tuples
};

struct conn_state {
    int fd; // Socket file descriptor
    int id; // Unique connection ID
    enum { CONN_CONNECTING, CONN_SENDING, CONN_READING, CONN_DONE, CONN_ERROR } state;
    struct sockaddr_in src_addr; // Source address
    struct sockaddr_in dst_addr; // Destination address
    int msg_sent;
    int msg_read;
    char readbuf[MAX_MSG];
    time_t start_time;
    time_t last_evt_time;
    struct src_tuple *tuple; // Pointer to tuple in use
};

// ========== Helpers ==========

void print_help(const char *prog) {
    printf("Usage:\n");
    printf("  %s -s <server IP> -p <server port> -n <total connections> -c <concurrency> -a <client IP range> -r <port range> [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -s <server IP>         IP address of the server\n");
    printf("  -p <server port>       Port number of the server\n");
    printf("  -n <total connections> Number of connections to make\n");
    printf("  -c <concurrency>       Max concurrent connections in flight (window size)\n");
    printf("  -a <client IP range>   Source IP range (e.g., 192.168.1.1-10)\n");
    printf("  -r <client port range> Source port range (e.g., 5000-5100)\n");
    printf("  -w <wait ms>           Wait time (ms) after each batch of connections\n");
    printf("  -k                     Force RST on close and add iptables rule\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -l <debug log file>    Write debug output to this file (default: ./tcp_client_debug.log)\n");
    printf("  -t <threads>           Number of threads (default: 4)\n");
    printf("  -h                     Show this help message\n");
    exit(0);
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Parse IP range into array of in_addr
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

// Parse port range into array of ints
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

void set_rst_and_close(int fd) {
    if (kill_flag) {
        struct linger sl = {1, 0};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        debug_print("[DEBUG] SO_LINGER set for RST on close for fd=%d", fd);
    }
    close(fd);
}

// ========== Threaded Connection Worker ==========

struct thread_args {
    int thread_id;
    struct src_tuple *tuples;
    int tuple_count;
    int total_connections;  // Number of connections this thread should make
    int max_concurrent;
    double wait_time_ms;
    struct sockaddr_in srv_addr;
    char *server_ip;
    int server_port;
};

void* connection_worker(void *arg) {
    struct thread_args *args = (struct thread_args*) arg;
    int started = 0, finished = 0, errors = 0;
    int tuple_last_used = 0;
    char write_msg[] = "hello\n";
    int progress_step = args->total_connections / 10;
    if (progress_step == 0) progress_step = 1;
    int progress = 0;
    struct epoll_event events[MAX_EVENTS];

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        fatal_print("epoll_create1 failed: %s", strerror(errno));
        pthread_exit(NULL);
    }

    while (started < args->total_connections && !global_stop) {
        int batch = (args->total_connections - started > args->max_concurrent) ? args->max_concurrent : (args->total_connections - started);
        struct conn_state **conns = calloc(batch, sizeof(struct conn_state*));
        int inflight = 0;

        for (int i = 0; i < batch && !global_stop; i++) {
            int t_idx = tuple_last_used;
            // Find a free tuple (in_use not needed, one thread per tuple set)
            tuple_last_used = (tuple_last_used + 1) % args->tuple_count;
            struct src_tuple *tuple = &args->tuples[t_idx];

            int fd = -1;
            int retry = 0;
            int connect_success = 0;
            struct sockaddr_in src_addr;
            char ipbuf[INET_ADDRSTRLEN];
            int connect_errno = 0;
            int res = -1;

            for (retry = 0; retry < CONNECT_RETRIES; ++retry) {
                atomic_fetch_add(&stat_total_connect_attempts, 1);
                fd = socket(AF_INET, SOCK_STREAM, 0);
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

                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr = tuple->ip;
                src_addr.sin_port = htons(tuple->port);
                inet_ntop(AF_INET, &src_addr.sin_addr, ipbuf, sizeof(ipbuf));

                // Reuseport & reuseaddr for high scalability
                int optval = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
#ifdef SO_REUSEPORT
                setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
#endif

                if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    fatal_print("[STAT][T%d] Technical error: bind() failed for %s:%d: %s", args->thread_id, ipbuf, tuple->port, strerror(errno));
                    close(fd);
                    continue;
                }

                res = connect(fd, (struct sockaddr *)&args->srv_addr, sizeof(args->srv_addr));
                if (res == 0) {
                    connect_success = 1;
                    debug_print("[DEBUG][T%d][Conn %d][Retry %d] connect() immediate success src %s:%d -> dst %s:%d", args->thread_id, started + i, retry+1, ipbuf, tuple->port, args->server_ip, args->server_port);
                    break;
                } else if (errno == EINPROGRESS) {
                    connect_success = 1;
                    debug_print("[DEBUG][T%d][Conn %d][Retry %d] connect() in progress src %s:%d -> dst %s:%d", args->thread_id, started + i, retry+1, ipbuf, tuple->port, args->server_ip, args->server_port);
                    break;
                } else {
                    connect_errno = errno;
                    if (errno == ECONNREFUSED) {
                        atomic_fetch_add(&stat_server_busy, 1);
                        fatal_print("[STAT][T%d] Server busy/refused: connect() failed: %s, src %s:%d -> dst %s:%d", args->thread_id, strerror(errno), ipbuf, tuple->port, args->server_ip, args->server_port);
                    } else if (errno == ENETUNREACH || errno == ETIMEDOUT || errno == EHOSTUNREACH) {
                        atomic_fetch_add(&stat_handshake_failed, 1);
                        fatal_print("[STAT][T%d] Handshake never completed (network unreachable/timeout): connect() failed: %s, src %s:%d -> dst %s:%d", args->thread_id, strerror(errno), ipbuf, tuple->port, args->server_ip, args->server_port);
                    } else if (errno == EMFILE || errno == ENFILE) {
                        atomic_fetch_add(&stat_local_resource_exhausted, 1);
                        fatal_print("[STAT][T%d] Local resource exhaustion: connect() failed: %s, src %s:%d -> dst %s:%d", args->thread_id, strerror(errno), ipbuf, tuple->port, args->server_ip, args->server_port);
                    } else {
                        atomic_fetch_add(&stat_technical_error, 1);
                        fatal_print("[STAT][T%d] Technical error: connect() failed: %s, src %s:%d -> dst %s:%d", args->thread_id, strerror(errno), ipbuf, tuple->port, args->server_ip, args->server_port);
                    }
                    set_rst_and_close(fd);
                    usleep(CONNECT_RETRY_DELAY_MS * 1000);
                    continue;
                }
            }
            if (!connect_success) {
                errors++;
                continue;
            }

            struct conn_state *cs = calloc(1, sizeof(struct conn_state));
            cs->fd = fd;
            cs->id = started + i;
            cs->state = (res == 0) ? CONN_SENDING : CONN_CONNECTING;
            cs->src_addr = src_addr;
            cs->dst_addr = args->srv_addr;
            cs->msg_sent = 0;
            cs->msg_read = 0;
            cs->start_time = time(NULL);
            cs->last_evt_time = cs->start_time;
            cs->tuple = tuple;

            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.ptr = cs;
            ev.events = (cs->state == CONN_CONNECTING) ? EPOLLOUT : EPOLLOUT;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                perror("epoll_ctl ADD");
                fatal_print("[STAT][T%d] Technical error: epoll_ctl ADD failed: %s", args->thread_id, strerror(errno));
                set_rst_and_close(fd); free(cs); continue;
            }
            conns[inflight] = cs;
            inflight++;
        }

        // Event loop for batch
        int batch_finished = 0;
        while (batch_finished < inflight && !global_stop) {
            int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
            time_t now = time(NULL);

            // Timeout checks (connect/read)
            for (int i = 0; i < inflight; ++i) {
                struct conn_state *cs = conns[i];
                if (!cs) continue;
                if (cs->state == CONN_CONNECTING && (now - cs->start_time) > CONNECT_TIMEOUT_SEC) {
                    atomic_fetch_add(&stat_handshake_failed, 1);
                    debug_print("[DEBUG][T%d][Conn %d] connect() timeout", args->thread_id, cs->id);
                    fatal_print("[STAT][T%d] Handshake never completed (connect timeout) src %s:%d -> dst %s:%d", args->thread_id, inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; errors++; free(cs); conns[i] = NULL; batch_finished++;
                } else if (cs->state == CONN_READING && (now - cs->last_evt_time) > REPLY_TIMEOUT_SEC) {
                    atomic_fetch_add(&stat_read_timeout, 1);
                    debug_print("[DEBUG][T%d][Conn %d] read() timeout after %d bytes", args->thread_id, cs->id, cs->msg_read);
                    fatal_print("[STAT][T%d] Read timeout after handshake: src %s:%d -> dst %s:%d", args->thread_id, inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; errors++; free(cs); conns[i] = NULL; batch_finished++;
                }
            }

            if (n < 0) {
                if (errno == EINTR) continue;
                atomic_fetch_add(&stat_technical_error, 1);
                perror("epoll_wait");
                fatal_print("[STAT][T%d] Technical error: epoll_wait failed: %s", args->thread_id, strerror(errno));
                break;
            }
            for (int i = 0; i < n; ++i) {
                struct conn_state *cs = events[i].data.ptr;
                if (!cs) continue;
                int idx2 = -1;
                for (int k = 0; k < inflight; ++k) if (conns[k] == cs) { idx2 = k; break; }
                if (idx2 == -1) continue;

                if (cs->state == CONN_CONNECTING) {
                    int err = 0; socklen_t len = sizeof(err);
                    if (getsockopt(cs->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
                        if (err == ECONNREFUSED) {
                            atomic_fetch_add(&stat_server_busy, 1);
                            fatal_print("[STAT][T%d] Server busy/refused: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", args->thread_id, strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else if (err == ENETUNREACH || err == ETIMEDOUT || err == EHOSTUNREACH) {
                            atomic_fetch_add(&stat_handshake_failed, 1);
                            fatal_print("[STAT][T%d] Handshake never completed (getsockopt/timeout): %s src %s:%d -> dst %s:%d", args->thread_id, strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else if (err == EMFILE || err == ENFILE) {
                            atomic_fetch_add(&stat_local_resource_exhausted, 1);
                            fatal_print("[STAT][T%d] Local resource exhaustion: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", args->thread_id, strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else {
                            atomic_fetch_add(&stat_technical_error, 1);
                            fatal_print("[STAT][T%d] Technical error: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", args->thread_id, strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        }
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    debug_print("[DEBUG][T%d][Conn %d] connect() complete", args->thread_id, cs->id);
                    cs->last_evt_time = time(NULL);
                    cs->state = CONN_SENDING;
                    struct epoll_event ev; memset(&ev, 0, sizeof(ev));
                    ev.data.ptr = cs; ev.events = EPOLLOUT;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, cs->fd, &ev);
                } else if (cs->state == CONN_SENDING && (events[i].events & EPOLLOUT)) {
                    ssize_t wr = send(cs->fd, write_msg + cs->msg_sent, MAX_MSG - cs->msg_sent, 0);
                    if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                    else if (wr < 0) {
                        atomic_fetch_add(&stat_technical_error, 1);
                        debug_print("[DEBUG][T%d][Conn %d] send() error: %s", args->thread_id, cs->id, strerror(errno));
                        fatal_print("[STAT][T%d] Technical error: send() error: %s src %s:%d -> dst %s:%d", args->thread_id,
                            strerror(errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    cs->msg_sent += wr;
                    if (cs->msg_sent == MAX_MSG) {
                        debug_print("[DEBUG][T%d][Conn %d] sent %d bytes", args->thread_id, cs->id, cs->msg_sent);
                        cs->state = CONN_READING; cs->last_evt_time = time(NULL);
                        struct epoll_event ev; memset(&ev, 0, sizeof(ev));
                        ev.data.ptr = cs; ev.events = EPOLLIN;
                        epoll_ctl(epfd, EPOLL_CTL_MOD, cs->fd, &ev);
                    }
                } else if (cs->state == CONN_READING && (events[i].events & EPOLLIN)) {
                    ssize_t rd = recv(cs->fd, cs->readbuf + cs->msg_read, MAX_MSG - cs->msg_read, 0);
                    if (rd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                    else if (rd <= 0) {
                        atomic_fetch_add(&stat_technical_error, 1);
                        debug_print("[DEBUG][T%d][Conn %d] recv() error or closed: %s", args->thread_id, cs->id, strerror(errno));
                        fatal_print("[STAT][T%d] Technical error: recv() error or closed: %s src %s:%d -> dst %s:%d", args->thread_id,
                            strerror(errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    cs->msg_read += rd;
                    cs->last_evt_time = time(NULL);
                    if (cs->msg_read == MAX_MSG) {
                        atomic_fetch_add(&stat_connection_closed, 1);
                        debug_print("[STAT][T%d][Conn %d] Connection closed normally (success)", args->thread_id, cs->id);
                        cs->state = CONN_DONE;
                        set_rst_and_close(cs->fd); finished++;
                        free(cs); conns[idx2] = NULL; batch_finished++;
                        progress++;
                        if (progress_step && progress % progress_step == 0) {
                            printf("[T%d] Progress: %d/%d (%d%%)\n", args->thread_id, progress, args->total_connections, (progress * 100) / args->total_connections);
                            fflush(stdout);
                        }
                    }
                }
            }
        }
        free(conns);
        if (args->wait_time_ms > 0 && started + batch < args->total_connections) {
            debug_print("[DEBUG][T%d] Sleeping %.2f ms after batch", args->thread_id, args->wait_time_ms);
            usleep((useconds_t)(args->wait_time_ms * 1000));
        }
        started += batch;
    }
    debug_print("[SUMMARY][T%d] Completed %d connections (%d errors)", args->thread_id, args->total_connections, errors);
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
    int total_connections = 0;
    int max_concurrent = 0;
    char *client_ip_range = NULL;
    char *client_port_range = NULL;
    double wait_time_ms = 0;
    char *debug_log_file = NULL;
    int num_threads = 4; // Default

    // Parse options
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:a:r:w:kDhl:t:")) != -1) {
        switch (opt) {
            case 's': server_ip = strdup(optarg); break;
            case 'p': server_port = atoi(optarg); break;
            case 'n': total_connections = atoi(optarg); break;
            case 'c': max_concurrent = atoi(optarg); break;
            case 'a': client_ip_range = strdup(optarg); break;
            case 'r': client_port_range = strdup(optarg); break;
            case 'w': wait_time_ms = atof(optarg); break;
            case 'k': kill_flag = true; break;
            case 'D': debug_mode = true; break;
            case 'l': debug_log_file = strdup(optarg); break;
            case 't': num_threads = atoi(optarg); break;
            case 'h': print_help(argv[0]);
            default:  print_help(argv[0]);
        }
    }
    if (!server_ip || !server_port || total_connections <= 0 || max_concurrent <= 0 || !client_ip_range || !client_port_range) {
        print_help(argv[0]);
    }
    if (!debug_log_file) {
        debug_log_file = strdup("./tcp_client_debug.log");
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
    if (total_connections > tuple_count) {
        fatal_print("total_connections (-n) cannot exceed unique (ip,port) tuples (%d).", tuple_count);
        exit(1);
    }
    if (max_concurrent > tuple_count) {
        fatal_print("max_concurrent (-c) cannot exceed unique (ip,port) tuples (%d).", tuple_count);
        exit(1);
    }
    if (num_threads < 1) num_threads = 1;
    if (num_threads > num_source_ips) num_threads = num_source_ips; // Can't have more threads than IPs

    debug_print("[DEBUG] Connecting to server %s:%d, total connections: %d, concurrency: %d, tuples: %d, wait: %.2f ms, kill_flag: %d, threads: %d",
                server_ip, server_port, total_connections, max_concurrent, tuple_count, wait_time_ms, kill_flag, num_threads);

    // iptables rule for RST (if requested)
    if (kill_flag) {
        const char *add_command = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Adding iptables rule to drop RSTs...");
        if (system(add_command) != 0) {
            fatal_print("Failed to add iptables rule");
            exit(1);
        }
        debug_print("[DEBUG] iptables rule added");
    }

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

    // Calculate per-thread connection counts
    int *conn_per_thread = calloc(num_threads, sizeof(int));
    rem = total_connections % num_threads;
    base = total_connections / num_threads;
    for (int i = 0, acc = 0; i < num_threads; i++) {
        conn_per_thread[i] = base + (i < rem ? 1 : 0);
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
    int conn_accum = 0;
    for (int t = 0; t < num_threads; t++) {
        int ips_this = ips_per_thread[t];
        int tuples_this = ips_this * num_source_ports;
        struct src_tuple *tuples = calloc(tuples_this, sizeof(struct src_tuple));
        int idx = 0;
        for (int i = ip_start_idx; i < ip_start_idx + ips_this; i++) {
            for (int j = 0; j < num_source_ports; j++) {
                tuples[idx].ip = source_ips[i];
                tuples[idx].port = source_ports[j];
                tuples[idx].in_use = false;
                idx++;
            }
        }
        ip_start_idx += ips_this;

        targs[t].thread_id = t;
        targs[t].tuples = tuples;
        targs[t].tuple_count = tuples_this;
        targs[t].total_connections = conn_per_thread[t];
        targs[t].max_concurrent = max_inflight_per_thread[t];
        targs[t].wait_time_ms = wait_time_ms;
        targs[t].srv_addr = srv_addr;
        targs[t].server_ip = server_ip;
        targs[t].server_port = server_port;

        pthread_create(&tids[t], NULL, connection_worker, &targs[t]);
    }

    // Wait for all threads
    for (int t = 0; t < num_threads; t++) {
        pthread_join(tids[t], NULL);
        free(targs[t].tuples);
    }

    printf("Completed %d connections\n", total_connections);
    print_stats();

    if (kill_flag) {
        const char *del_command = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Removing iptables rule...");
        system(del_command);
        debug_print("[DEBUG] iptables rule removed");
    }

    // Clean up
    free(ips_per_thread);
    free(conn_per_thread);
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
