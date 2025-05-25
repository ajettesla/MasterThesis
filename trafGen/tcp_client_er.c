/**
 * Epoll-based TCP client with unique (source IP, source port) per connection.
 * Enhanced: Prints statistics on connection outcomes on exit (Ctrl-C/SIGINT/SIGTERM).
 * All statistics are tagged with [STAT] in logs for easy identification.
 * 
 * Usage and options as in your original code.
 */

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

// Constants for the program's operation
#define MAX_EVENTS 1024
#define MAX_MSG 6
#define CONNECT_TIMEOUT_SEC 3
#define REPLY_TIMEOUT_SEC 2
#define CONNECT_RETRIES 6
#define CONNECT_RETRY_DELAY_MS 100

// Flags for debug mode and RST-close behavior
static bool debug_mode = false;
static bool kill_flag = false;
static FILE *debug_log = NULL;

// Atomic counters for connection outcome statistics
static atomic_int stat_local_resource_exhausted = 0;     // Local resource (FD) exhaustion
static atomic_int stat_server_busy = 0;                  // Server busy (ECONNREFUSED or similar)
static atomic_int stat_handshake_failed = 0;             // TCP handshake never completed
static atomic_int stat_read_timeout = 0;                 // Read timeout after connect
static atomic_int stat_connection_timeout = 0;           // Connect timeout (SYN sent, no reply)
static atomic_int stat_connection_closed = 0;            // Connections closed normally (data exchanged)
static atomic_int stat_technical_error = 0;              // Other technical errors (bind, epoll, etc.)
static atomic_int stat_total_connect_attempts = 0;       // For info

// Open the debug log file for writing (line buffered)
void open_debug_log(const char *filename) {
    debug_log = fopen(filename, "a");
    if (!debug_log) {
        fprintf(stderr, "Failed to open debug log file %s: %s\n", filename, strerror(errno));
        exit(2);
    }
    setvbuf(debug_log, NULL, _IOLBF, 0); // Line-buffered
}

// Close the debug log file if open
void close_debug_log() {
    if (debug_log) {
        fclose(debug_log);
        debug_log = NULL;
    }
}

// Print a debug message to the debug log if enabled
void debug_print(const char *fmt, ...) {
    if (debug_mode && debug_log) {
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_log, fmt, args);
        fprintf(debug_log, "\n");
        va_end(args);
    }
}

// Print a fatal error message to the debug log or stderr
void fatal_print(const char *fmt, ...) {
    if (debug_log) {
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_log, fmt, args);
        fprintf(debug_log, "\n");
        va_end(args);
    } else {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
    }
}

// Print connection outcome statistics to stderr and the log, tagged [STAT]
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
    }
}

// Signal handler for Ctrl-C/SIGINT/SIGTERM: print stats and exit
void handle_sigint(int signo) {
    print_stats();
    if (debug_log) fflush(debug_log);
    _exit(130); // Exit code 130 for Ctrl-C
}

// Structure for a (source IP, source port) tuple, and whether it's in use
struct src_tuple {
    struct in_addr ip;
    int port;
    bool in_use;
};

// Per-connection state for event-driven handling
struct conn_state {
    int fd; // Socket file descriptor
    int id; // Unique connection ID
    enum { CONN_CONNECTING, CONN_SENDING, CONN_READING, CONN_DONE, CONN_ERROR } state; // Connection state
    struct sockaddr_in src_addr; // Source address
    struct sockaddr_in dst_addr; // Destination (server) address
    int msg_sent; // Bytes sent
    int msg_read; // Bytes read
    char readbuf[MAX_MSG]; // Read buffer
    time_t start_time; // Start time of connection
    time_t last_evt_time; // Last event time
    struct src_tuple *tuple; // Pointer to tuple in use
};

// Print help/usage message and exit
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
    printf("  -h                     Show this help message\n");
    printf("  -l <debug log file>    Write debug output to this file (default: ./tcp_client_debug.log)\n");
    exit(0);
}

// Set the socket to non-blocking mode
int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Parse an IP range string (e.g., "192.168.1.1-10" or "192.168.1.1-192.168.1.20") into an array of in_addr
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

// Parse a port range string (e.g., "5000-5100") into an array of ports
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

// Set SO_LINGER to force RST on close if requested, then close the socket
void set_rst_and_close(int fd) {
    if (kill_flag) {
        struct linger sl = {1, 0};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        debug_print("[DEBUG] SO_LINGER set for RST on close for fd=%d", fd);
    }
    close(fd);
}

// Pick a free (source IP, port) tuple for a new connection, round-robin
int pick_free_tuple(struct src_tuple *tuples, int total, int *last_used) {
    int start = *last_used;
    for (int i = 0; i < total; i++) {
        int idx = (start + i) % total;
        if (!tuples[idx].in_use) {
            tuples[idx].in_use = true;
            *last_used = (idx + 1) % total;
            return idx;
        }
    }
    return -1; // none available
}

// Mark a tuple as free (no longer in use)
void release_tuple(struct src_tuple *tuple) {
    tuple->in_use = false;
}

int main(int argc, char **argv) {
    // Set up SIGINT/SIGTERM handler so stats print on Ctrl-C or kill
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Command line option variables
    char *server_ip = NULL;
    int server_port = 0;
    int total_connections = 0;
    int max_concurrent = 0;
    char *client_ip_range = NULL;
    char *client_port_range = NULL;
    double wait_time_ms = 0;
    char *debug_log_file = NULL;

    // Parse command line options
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:a:r:w:kDhl:")) != -1) {
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
            case 'h': print_help(argv[0]);
            default:  print_help(argv[0]);
        }
    }
    // Check required options
    if (!server_ip || !server_port || total_connections <= 0 || max_concurrent <= 0 || !client_ip_range || !client_port_range) {
        print_help(argv[0]);
    }
    // If no log file given, use default
    if (!debug_log_file) {
        debug_log_file = strdup("./tcp_client_debug.log");
    }
    open_debug_log(debug_log_file);

    // Parse the source IP and port ranges
    struct in_addr *source_ips = NULL;
    int num_source_ips = 0;
    int *source_ports = NULL;
    int num_source_ports = 0;
    parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
    parse_port_range(client_port_range, &source_ports, &num_source_ports);

    // Build all possible unique (ip, port) tuples
    int tuple_count = num_source_ips * num_source_ports;
    struct src_tuple *tuples = calloc(tuple_count, sizeof(struct src_tuple));
    int idx = 0;
    for (int i = 0; i < num_source_ips; i++) {
        for (int j = 0; j < num_source_ports; j++) {
            tuples[idx].ip = source_ips[i];
            tuples[idx].port = source_ports[j];
            tuples[idx].in_use = false;
            idx++;
        }
    }

    // Sanity checks: cannot exceed number of tuples
    if (total_connections > tuple_count) {
        fatal_print("total_connections (-n) cannot exceed unique (ip,port) tuples (%d). Reduce -n or increase IP/port range.", tuple_count);
        exit(1);
    }
    if (max_concurrent > tuple_count) {
        fatal_print("max_concurrent (-c) cannot exceed unique (ip,port) tuples (%d). Reduce -c or increase IP/port range.", tuple_count);
        exit(1);
    }

    debug_print("[DEBUG] Connecting to server %s:%d, total connections: %d, concurrency: %d, tuples: %d, wait: %.2f ms, kill_flag: %d",
                server_ip, server_port, total_connections, max_concurrent, tuple_count, wait_time_ms, kill_flag);

    // Optionally add iptables rule to drop RST packets (for -k)
    if (kill_flag) {
        const char *add_command = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Adding iptables rule to drop RSTs...");
        if (system(add_command) != 0) {
            fatal_print("Failed to add iptables rule");
            exit(1);
        }
        debug_print("[DEBUG] iptables rule added");
    }

    // Prepare sockaddr_in for server
    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) != 1) {
        fatal_print("Invalid server IP: %s", server_ip);
        exit(1);
    }

    // Create the epoll instance for async event handling
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        fatal_print("epoll_create1 failed: %s", strerror(errno));
        exit(1);
    }

    // Main stats and state variables
    int started = 0, finished = 0, errors = 0;
    int tuple_last_used = 0;
    char write_msg[] = "hello\n";
    int progress_step = total_connections / 10;
    if (progress_step == 0) progress_step = 1;
    int progress = 0;
    struct epoll_event events[MAX_EVENTS];

    // Main connection batch loop
    while (started < total_connections) {
        // Determine batch size (max concurrent connections or less if fewer remain)
        int batch = (total_connections - started > max_concurrent) ? max_concurrent : (total_connections - started);
        struct conn_state **conns = calloc(batch, sizeof(struct conn_state *));
        int inflight = 0;

        // Start all connections in the batch
        for (int i = 0; i < batch; i++) {
            int t_idx = pick_free_tuple(tuples, tuple_count, &tuple_last_used);
            if (t_idx < 0) {
                fatal_print("No free (IP,port) tuple! This should not happen.");
                exit(1);
            }
            struct src_tuple *tuple = &tuples[t_idx];

            int fd = -1;
            int retry = 0;
            int connect_success = 0;
            struct sockaddr_in src_addr;
            char ipbuf[INET_ADDRSTRLEN];
            int connect_errno = 0;
            int res = -1;

            // Try to establish the connection, with up to CONNECT_RETRIES attempts
            for (retry = 0; retry < CONNECT_RETRIES; ++retry) {
                atomic_fetch_add(&stat_total_connect_attempts, 1);
                fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) {
                    // Local resource exhaustion or technical error
                    if (errno == EMFILE || errno == ENFILE) {
                        atomic_fetch_add(&stat_local_resource_exhausted, 1);
                        fatal_print("[STAT] Local resource exhaustion: socket() failed with %s", strerror(errno));
                    } else {
                        atomic_fetch_add(&stat_technical_error, 1);
                        fatal_print("[STAT] Technical error: socket() failed with %s", strerror(errno));
                    }
                    continue;
                }
                if (set_nonblock(fd) < 0) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    fatal_print("[STAT] Technical error: set_nonblock failed: %s", strerror(errno));
                    close(fd);
                    continue;
                }

                // Prepare source address for bind()
                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr = tuple->ip;
                src_addr.sin_port = htons(tuple->port);
                inet_ntop(AF_INET, &src_addr.sin_addr, ipbuf, sizeof(ipbuf));

                // Bind the socket to the source IP:port tuple
                if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                    atomic_fetch_add(&stat_technical_error, 1);
                    fatal_print("[STAT] Technical error: bind() failed for %s:%d: %s", ipbuf, tuple->port, strerror(errno));
                    close(fd);
                    continue;
                }

                // Try to connect to the server
                res = connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                if (res == 0) {
                    // Immediate connect success (very rare)
                    connect_success = 1;
                    debug_print("[DEBUG][Conn %d][Retry %d] connect() immediate success src %s:%d -> dst %s:%d", started + i, retry+1, ipbuf, tuple->port, server_ip, server_port);
                    break;
                } else if (errno == EINPROGRESS) {
                    // Non-blocking connect in progress
                    connect_success = 1;
                    debug_print("[DEBUG][Conn %d][Retry %d] connect() in progress src %s:%d -> dst %s:%d", started + i, retry+1, ipbuf, tuple->port, server_ip, server_port);
                    break;
                } else {
                    // Connect failed: categorize
                    connect_errno = errno;
                    if (errno == ECONNREFUSED) {
                        atomic_fetch_add(&stat_server_busy, 1);
                        fatal_print("[STAT] Server busy/refused: connect() failed: %s, src %s:%d -> dst %s:%d", strerror(errno), ipbuf, tuple->port, server_ip, server_port);
                    } else if (errno == ENETUNREACH || errno == ETIMEDOUT || errno == EHOSTUNREACH) {
                        atomic_fetch_add(&stat_handshake_failed, 1);
                        fatal_print("[STAT] Handshake never completed (network unreachable/timeout): connect() failed: %s, src %s:%d -> dst %s:%d", strerror(errno), ipbuf, tuple->port, server_ip, server_port);
                    } else if (errno == EMFILE || errno == ENFILE) {
                        atomic_fetch_add(&stat_local_resource_exhausted, 1);
                        fatal_print("[STAT] Local resource exhaustion: connect() failed: %s, src %s:%d -> dst %s:%d", strerror(errno), ipbuf, tuple->port, server_ip, server_port);
                    } else {
                        atomic_fetch_add(&stat_technical_error, 1);
                        fatal_print("[STAT] Technical error: connect() failed: %s, src %s:%d -> dst %s:%d", strerror(errno), ipbuf, tuple->port, server_ip, server_port);
                    }
                    set_rst_and_close(fd);
                    usleep(CONNECT_RETRY_DELAY_MS * 1000);
                    continue;
                }
            }
            if (!connect_success) {
                release_tuple(tuple);
                errors++;
                continue;
            }

            // Allocate and initialize per-connection state
            struct conn_state *cs = calloc(1, sizeof(struct conn_state));
            cs->fd = fd;
            cs->id = started + i;
            cs->state = (res == 0) ? CONN_SENDING : CONN_CONNECTING;
            cs->src_addr = src_addr;
            cs->dst_addr = srv_addr;
            cs->msg_sent = 0;
            cs->msg_read = 0;
            cs->start_time = time(NULL);
            cs->last_evt_time = cs->start_time;
            cs->tuple = tuple;

            // Register the socket with epoll for async events
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.ptr = cs;
            ev.events = (cs->state == CONN_CONNECTING) ? EPOLLOUT : EPOLLOUT;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                atomic_fetch_add(&stat_technical_error, 1);
                perror("epoll_ctl ADD");
                fatal_print("[STAT] Technical error: epoll_ctl ADD failed: %s", strerror(errno));
                set_rst_and_close(fd); release_tuple(tuple); free(cs); continue;
            }
            conns[inflight] = cs;
            inflight++;
        }

        // Event loop for the current batch of connections
        int batch_finished = 0;
        while (batch_finished < inflight) {
            int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
            time_t now = time(NULL);

            // Check for timeouts (connect and read)
            for (int i = 0; i < inflight; ++i) {
                struct conn_state *cs = conns[i];
                if (!cs) continue;
                if (cs->state == CONN_CONNECTING && (now - cs->start_time) > CONNECT_TIMEOUT_SEC) {
                    atomic_fetch_add(&stat_handshake_failed, 1);
                    debug_print("[DEBUG][Conn %d] connect() timeout", cs->id);
                    fatal_print("[STAT] Handshake never completed (connect timeout) src %s:%d -> dst %s:%d", inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[i] = NULL; batch_finished++;
                } else if (cs->state == CONN_READING && (now - cs->last_evt_time) > REPLY_TIMEOUT_SEC) {
                    atomic_fetch_add(&stat_read_timeout, 1);
                    debug_print("[DEBUG][Conn %d] read() timeout after %d bytes", cs->id, cs->msg_read);
                    fatal_print("[STAT] Read timeout after handshake: src %s:%d -> dst %s:%d", inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[i] = NULL; batch_finished++;
                }
            }

            if (n < 0) {
                if (errno == EINTR) continue;
                atomic_fetch_add(&stat_technical_error, 1);
                perror("epoll_wait");
                fatal_print("[STAT] Technical error: epoll_wait failed: %s", strerror(errno));
                break;
            }
            for (int i = 0; i < n; ++i) {
                struct conn_state *cs = events[i].data.ptr;
                if (!cs) continue;
                int idx2 = -1;
                for (int k = 0; k < inflight; ++k) if (conns[k] == cs) { idx2 = k; break; }
                if (idx2 == -1) continue;

                // Handle epoll event for connection in each state
                if (cs->state == CONN_CONNECTING) {
                    int err = 0; socklen_t len = sizeof(err);
                    if (getsockopt(cs->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
                        if (err == ECONNREFUSED) {
                            atomic_fetch_add(&stat_server_busy, 1);
                            fatal_print("[STAT] Server busy/refused: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else if (err == ENETUNREACH || err == ETIMEDOUT || err == EHOSTUNREACH) {
                            atomic_fetch_add(&stat_handshake_failed, 1);
                            fatal_print("[STAT] Handshake never completed (getsockopt/timeout): %s src %s:%d -> dst %s:%d", strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else if (err == EMFILE || err == ENFILE) {
                            atomic_fetch_add(&stat_local_resource_exhausted, 1);
                            fatal_print("[STAT] Local resource exhaustion: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        } else {
                            atomic_fetch_add(&stat_technical_error, 1);
                            fatal_print("[STAT] Technical error: getsockopt/conn failed: %s src %s:%d -> dst %s:%d", strerror(err ? err : errno),
                                inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                                inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        }
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    debug_print("[DEBUG][Conn %d] connect() complete", cs->id);
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
                        debug_print("[DEBUG][Conn %d] send() error: %s", cs->id, strerror(errno));
                        fatal_print("[STAT] Technical error: send() error: %s src %s:%d -> dst %s:%d", cs->id,
                            strerror(errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    cs->msg_sent += wr;
                    if (cs->msg_sent == MAX_MSG) {
                        debug_print("[DEBUG][Conn %d] sent %d bytes", cs->id, cs->msg_sent);
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
                        debug_print("[DEBUG][Conn %d] recv() error or closed: %s", cs->id, strerror(errno));
                        fatal_print("[STAT] Technical error: recv() error or closed: %s src %s:%d -> dst %s:%d", cs->id,
                            strerror(errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    cs->msg_read += rd;
                    cs->last_evt_time = time(NULL);
                    if (cs->msg_read == MAX_MSG) {
                        atomic_fetch_add(&stat_connection_closed, 1);
                        debug_print("[STAT][Conn %d] Connection closed normally (success)", cs->id);
                        cs->state = CONN_DONE;
                        set_rst_and_close(cs->fd); release_tuple(cs->tuple); finished++;
                        free(cs); conns[idx2] = NULL; batch_finished++;
                        progress++;
                        if (progress_step && progress % progress_step == 0) {
                            printf("Progress: %d/%d (%d%%)\n", progress, total_connections, (progress * 100) / total_connections);
                            fflush(stdout);
                        }
                    }
                }
            }
        }
        free(conns);

        // Optional wait after each batch
        if (wait_time_ms > 0 && started + batch < total_connections) {
            debug_print("[DEBUG] Sleeping %.2f ms after batch", wait_time_ms);
            usleep((useconds_t)(wait_time_ms * 1000));
        }
        started += batch;
    }
    printf("Completed %d connections (%d errors)\n", total_connections, errors);
    debug_print("[SUMMARY] Completed %d connections (%d errors)", total_connections, errors);

    // Print summary statistics at normal program exit
    print_stats();

    // Remove iptables rule if it was added
    if (kill_flag) {
        const char *del_command = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Removing iptables rule...");
        system(del_command);
        debug_print("[DEBUG] iptables rule removed");
    }

    // Free all dynamically allocated memory
    free(tuples);
    free(source_ips);
    free(source_ports);
    free(server_ip);
    if (client_ip_range) free(client_ip_range);
    if (client_port_range) free(client_port_range);
    close(epfd);
    close_debug_log();
    if (debug_log_file) free(debug_log_file);
    return 0;
}
