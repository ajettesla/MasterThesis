/**
 * Epoll-based TCP client with unique (source IP, source port) per connection.
 * Does NOT reuse any (IP,port) tuple until all connections are done.
 * Waits once per batch of concurrent connections (-c), for -w ms after batch.
 * Supports -a (IP range), -r (port range), -k (RST+iptables), -n (total), -c (concurrency), -w (batch wait, ms), -D (debug).
 * Retries connect() up to 6 times on failure before giving up.
 *
 * Usage:
 *   ./tcp_client_epoll_no_reuse_retry -s <server IP> -p <server port> -n <total> -c <concurrency> -a <IP range> -r <port range> [-w <ms>] [-k] [-D]
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

#define MAX_EVENTS 1024
#define MAX_MSG 6
#define CONNECT_TIMEOUT_SEC 3
#define REPLY_TIMEOUT_SEC 2
#define CONNECT_RETRIES 6
#define CONNECT_RETRY_DELAY_MS 100

static bool debug_mode = false;
static bool kill_flag = false;
static FILE *debug_log = NULL;

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
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_log, fmt, args);
        fprintf(debug_log, "\n");
        va_end(args);
    }
}

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

struct src_tuple {
    struct in_addr ip;
    int port;
    bool in_use;
};

struct conn_state {
    int fd;
    int id;
    enum { CONN_CONNECTING, CONN_SENDING, CONN_READING, CONN_DONE, CONN_ERROR } state;
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    int msg_sent;
    int msg_read;
    char readbuf[MAX_MSG];
    time_t start_time;
    time_t last_evt_time;
    struct src_tuple *tuple;
};

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

void set_rst_and_close(int fd) {
    if (kill_flag) {
        struct linger sl = {1, 0};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        debug_print("[DEBUG] SO_LINGER set for RST on close for fd=%d", fd);
    }
    close(fd);
}

int pick_free_tuple(struct src_tuple *tuples, int total, int *last_used) {
    // Pick next free tuple, round-robin
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

void release_tuple(struct src_tuple *tuple) {
    tuple->in_use = false;
}

int main(int argc, char **argv) {
    char *server_ip = NULL;
    int server_port = 0;
    int total_connections = 0;
    int max_concurrent = 0;
    char *client_ip_range = NULL;
    char *client_port_range = NULL;
    double wait_time_ms = 0;
    char *debug_log_file = NULL;

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
            default:
                print_help(argv[0]);
        }
    }
    if (!server_ip || !server_port || total_connections <= 0 || max_concurrent <= 0 || !client_ip_range || !client_port_range) {
        print_help(argv[0]);
    }
    if (!debug_log_file) {
        debug_log_file = strdup("./tcp_client_debug.log");
    }
    open_debug_log(debug_log_file);

    struct in_addr *source_ips = NULL;
    int num_source_ips = 0;
    int *source_ports = NULL;
    int num_source_ports = 0;
    parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
    parse_port_range(client_port_range, &source_ports, &num_source_ports);

    // Build unique tuples (ip, port)
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

    // Add iptables rule if -k is set
    if (kill_flag) {
        const char *add_command = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Adding iptables rule to drop RSTs...");
        if (system(add_command) != 0) {
            fatal_print("Failed to add iptables rule");
            exit(1);
        }
        debug_print("[DEBUG] iptables rule added");
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) != 1) {
        fatal_print("Invalid server IP: %s", server_ip);
        exit(1);
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        fatal_print("epoll_create1 failed: %s", strerror(errno));
        exit(1);
    }

    int started = 0, finished = 0, errors = 0;
    int tuple_last_used = 0;
    char write_msg[] = "hello\n";
    int progress_step = total_connections / 10;
    if (progress_step == 0) progress_step = 1;
    int progress = 0;
    struct epoll_event events[MAX_EVENTS];

    while (started < total_connections) {
        int batch = (total_connections - started > max_concurrent) ? max_concurrent : (total_connections - started);
        struct conn_state **conns = calloc(batch, sizeof(struct conn_state *));
        int inflight = 0;

        // Start the batch
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

            for (retry = 0; retry < CONNECT_RETRIES; ++retry) {
                fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) {
                    fatal_print("socket() failed: %s", strerror(errno));
                    continue;
                }
                if (set_nonblock(fd) < 0) {
                    fatal_print("set_nonblock failed: %s", strerror(errno));
                    close(fd);
                    continue;
                }

                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr = tuple->ip;
                src_addr.sin_port = htons(tuple->port);
                inet_ntop(AF_INET, &src_addr.sin_addr, ipbuf, sizeof(ipbuf));

                if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                    debug_print("[DEBUG][Conn %d][Retry %d] Bind failed for %s:%d: %s", started + i, retry+1, ipbuf, tuple->port, strerror(errno));
                    fatal_print("[ERROR][Conn %d][Retry %d] Bind failed for %s:%d: %s", started + i, retry+1, ipbuf, tuple->port, strerror(errno));
                    close(fd);
                    continue;
                }

                res = connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                if (res == 0) {
                    connect_success = 1;
                    debug_print("[DEBUG][Conn %d][Retry %d] connect() immediate success src %s:%d -> dst %s:%d", started + i, retry+1, ipbuf, tuple->port, server_ip, server_port);
                    break;
                } else if (errno == EINPROGRESS) {
                    connect_success = 1;
                    debug_print("[DEBUG][Conn %d][Retry %d] connect() in progress src %s:%d -> dst %s:%d", started + i, retry+1, ipbuf, tuple->port, server_ip, server_port);
                    break;
                } else {
                    connect_errno = errno;
                    debug_print("[DEBUG][Conn %d][Retry %d] connect() failed: %s, src %s:%d -> dst %s:%d", started + i, retry+1, strerror(errno), ipbuf, tuple->port, server_ip, server_port);
                    fatal_print("[ERROR][Conn %d][Retry %d] connect() failed: %s, src %s:%d -> dst %s:%d", started + i, retry+1, strerror(errno), ipbuf, tuple->port, server_ip, server_port);
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

            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.ptr = cs;
            ev.events = (cs->state == CONN_CONNECTING) ? EPOLLOUT : EPOLLOUT;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                perror("epoll_ctl ADD");
                fatal_print("[ERROR][Conn %d] epoll_ctl ADD failed: %s", cs->id, strerror(errno));
                set_rst_and_close(fd); release_tuple(tuple); free(cs); continue;
            }
            conns[inflight] = cs;
            inflight++;
        }

        // Event loop for this batch
        int batch_finished = 0;
        while (batch_finished < inflight) {
            int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
            time_t now = time(NULL);

            // Scan for timeouts (connect, read)
            for (int i = 0; i < inflight; ++i) {
                struct conn_state *cs = conns[i];
                if (!cs) continue;
                if (cs->state == CONN_CONNECTING && (now - cs->start_time) > CONNECT_TIMEOUT_SEC) {
                    debug_print("[DEBUG][Conn %d] connect() timeout", cs->id);
                    fatal_print("[TIMEOUT][Conn %d] connect() timeout src %s:%d -> dst %s:%d", cs->id,
                        inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[i] = NULL; batch_finished++;
                } else if (cs->state == CONN_READING && (now - cs->last_evt_time) > REPLY_TIMEOUT_SEC) {
                    debug_print("[DEBUG][Conn %d] read() timeout after %d bytes", cs->id, cs->msg_read);
                    fatal_print("[TIMEOUT][Conn %d] read() timeout after %d bytes src %s:%d -> dst %s:%d",
                        cs->id, cs->msg_read, inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                        inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                    set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[i] = NULL; batch_finished++;
                }
            }

            if (n < 0) {
                if (errno == EINTR) continue;
                perror("epoll_wait");
                fatal_print("epoll_wait failed: %s", strerror(errno));
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
                        debug_print("[DEBUG][Conn %d] connect() failed: %s", cs->id, strerror(err ? err : errno));
                        fatal_print("[ERROR][Conn %d] connect() failed: %s src %s:%d -> dst %s:%d", cs->id,
                            strerror(err ? err : errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
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
                        debug_print("[DEBUG][Conn %d] send() error: %s", cs->id, strerror(errno));
                        fatal_print("[ERROR][Conn %d] send() error: %s src %s:%d -> dst %s:%d", cs->id,
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
                        debug_print("[DEBUG][Conn %d] recv() error or closed: %s", cs->id, strerror(errno));
                        fatal_print("[ERROR][Conn %d] recv() error or closed: %s src %s:%d -> dst %s:%d", cs->id,
                            strerror(errno),
                            inet_ntoa(cs->src_addr.sin_addr), ntohs(cs->src_addr.sin_port),
                            inet_ntoa(cs->dst_addr.sin_addr), ntohs(cs->dst_addr.sin_port));
                        set_rst_and_close(cs->fd); cs->state = CONN_ERROR; release_tuple(cs->tuple); errors++; free(cs); conns[idx2] = NULL; batch_finished++; continue;
                    }
                    cs->msg_read += rd;
                    cs->last_evt_time = time(NULL);
                    if (cs->msg_read == MAX_MSG) {
                        debug_print("[DEBUG][Conn %d] read %d bytes: '%.*s'", cs->id, cs->msg_read, cs->msg_read, cs->readbuf);
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

        if (wait_time_ms > 0 && started + batch < total_connections) {
            debug_print("[DEBUG] Sleeping %.2f ms after batch", wait_time_ms);
            usleep((useconds_t)(wait_time_ms * 1000));
        }
        started += batch;
    }
    printf("Completed %d connections (%d errors)\n", total_connections, errors);
    debug_print("[SUMMARY] Completed %d connections (%d errors)", total_connections, errors);

    if (kill_flag) {
        const char *del_command = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        debug_print("[DEBUG] Removing iptables rule...");
        system(del_command);
        debug_print("[DEBUG] iptables rule removed");
    }

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
