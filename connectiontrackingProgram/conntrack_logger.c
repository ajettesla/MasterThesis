#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <blake3.h>

// Replace with your SPSC queue implementation header
#include "spsc_queue.h"

#define MAX_MESSAGE_LEN 2048
#define SYSLOG_PORT "514"
#define MIN_BATCH_SIZE 5
#define BATCH_TIMEOUT_US 1000000
#define LOGFILE_PATH "/var/log/conntrack_logger.log"

// Configuration structure
struct config {
    char *syslog_ip;
    char *machine_name;
    int daemonize;
    int kill_daemons;
    int count_enabled;
    int debug_enabled;
    int hash_enabled; // For -H option
    int payload_enabled; // For --payload option
    char *src_range;
};

// Connection event data
struct conn_event {
    long long count;
    long long timestamp_ns;
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port;
    char protocol_str[16];
    const char *msg_type_str;
    uint32_t timeout;
    const char *assured_str;
    char hash[17]; // 16 hex chars + null terminator
    int type_num; // Numeric type
    int state_num; // Numeric state
    int proto_num; // Numeric protocol
};

// Event data for passing between threads
struct event_data {
    long long timestamp_ns;
    long long count;
    enum nf_conntrack_msg_type type;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t l4proto;
    uint32_t timeout;
    uint32_t status;
    uint8_t tcp_state; // 255 if not set
};

// Callback data
struct callback_data {
    spsc_queue_t *queue;
    atomic_int *overflow_flag;
    int count_enabled;
    int hash_enabled;
    int payload_enabled;
    atomic_llong *event_counter;
    const char *src_range;
};

// Syslog thread data
struct syslog_data {
    spsc_queue_t *queue;
    char *syslog_ip;
    int syslog_fd;
    char *machine_name;
    int count_enabled;
    int debug_enabled;
    int hash_enabled;
    int payload_enabled;
    atomic_size_t *bytes_transferred;
    atomic_int *overflow_flag;
};

static int global_debug_enabled = 0;

// Log with timestamp
void log_with_timestamp(const char *fmt, ...) {
    int is_debug = (strncmp(fmt, "[DEBUG]", 7) == 0);
    if (is_debug && !global_debug_enabled) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(stdout, "[%s.%03ld] ", timestr, tv.tv_usec / 1000);

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fflush(stdout);
}

// Help message
static void print_help(const char *progname) {
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -n, --machine-name <name> Specify machine name (required)\n");
    printf("  -l, --lsip <ip_address>   Specify syslog server IP/domain (required)\n");
    printf("  -d, --daemonize           Daemonize the program (optional)\n");
    printf("  -k, --kill                Kill all running daemons (optional)\n");
    printf("  -c, --count <yes|no>      Prepend event count to each event (optional)\n");
    printf("  -D, --debug               Enable debug logging (optional)\n");
    printf("  -H, --hash                Include BLAKE3 hash in log messages\n");
    printf("  -P, --payload             Include detailed payload tuple\n");
    printf("  -r, --src-range <range>   Filter events by source IP range (CIDR, e.g., 192.168.1.0/24)\n");
    printf("Note: At least one of -H or -P must be specified.\n");
}

// Parse command-line arguments
static int parse_config(int argc, char *argv[], struct config *cfg) {
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"machine-name", required_argument, 0, 'n'},
        {"lsip", required_argument, 0, 'l'},
        {"daemonize", no_argument, 0, 'd'},
        {"kill", no_argument, 0, 'k'},
        {"count", required_argument, 0, 'c'},
        {"debug", no_argument, 0, 'D'},
        {"hash", no_argument, 0, 'H'},
        {"payload", no_argument, 0, 'P'},
        {"src-range", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    int opt;
    cfg->syslog_ip = NULL;
    cfg->machine_name = NULL;
    cfg->daemonize = 0;
    cfg->kill_daemons = 0;
    cfg->count_enabled = 0;
    cfg->debug_enabled = 0;
    cfg->hash_enabled = 0;
    cfg->payload_enabled = 0;
    cfg->src_range = NULL;

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:DHPr:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(argv[0]); exit(0);
            case 'n': cfg->machine_name = optarg; break;
            case 'l': cfg->syslog_ip = optarg; break;
            case 'd': cfg->daemonize = 1; break;
            case 'k': cfg->kill_daemons = 1; break;
            case 'c':
                if (strcasecmp(optarg, "yes") == 0) cfg->count_enabled = 1;
                else cfg->count_enabled = 0;
                break;
            case 'D': cfg->debug_enabled = 1; break;
            case 'H': cfg->hash_enabled = 1; break;
            case 'P': cfg->payload_enabled = 1; break;
            case 'r': cfg->src_range = optarg; break;
            default: print_help(argv[0]); return 1;
        }
    }

    if (!cfg->kill_daemons && (!cfg->syslog_ip || !cfg->machine_name)) {
        log_with_timestamp("Syslog server IP/domain and machine name are required\n");
        print_help(argv[0]);
        return 1;
    }
    return 0;
}

static atomic_llong event_counter = 0;

// Check IP in CIDR range
int ip_in_range(const char *ip_str, const char *range) {
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) <= 0) return 0;

    char *range_copy = strdup(range);
    char *slash = strchr(range_copy, '/');
    if (!slash) {
        free(range_copy);
        return 0;
    }
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) {
        free(range_copy);
        return 0;
    }

    struct in_addr network;
    if (inet_pton(AF_INET, range_copy, &network) <= 0) {
        free(range_copy);
        return 0;
    }

    uint32_t ip_num = ntohl(ip.s_addr);
    uint32_t net_num = ntohl(network.s_addr);
    uint32_t mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
    free(range_copy);

    return (ip_num & mask) == (net_num & mask);
}

// BLAKE3 hash (64-bit output)
static void calculate_hash(const char *input, char *output) {
    unsigned char hash[8];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, strlen(input));
    blake3_hasher_finalize(&hasher, hash, 8);
    for (int i = 0; i < 8; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[16] = '\0';
}

// Extract conntrack event
static void extract_conn_event(struct event_data *ed, struct conn_event *event, int hash_enabled) {
    event->count = ed->count;
    event->timestamp_ns = ed->timestamp_ns;

    inet_ntop(AF_INET, &ed->src_addr, event->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ed->dst_addr, event->dst_ip, INET_ADDRSTRLEN);

    event->src_port = ed->src_port;
    event->dst_port = ed->dst_port;

    if (ed->l4proto == IPPROTO_TCP) strcpy(event->protocol_str, "tcp");
    else if (ed->l4proto == IPPROTO_UDP) strcpy(event->protocol_str, "udp");
    else snprintf(event->protocol_str, sizeof(event->protocol_str), "proto %d", ed->l4proto);

    switch (ed->type) {
        case NFCT_T_NEW: event->msg_type_str = "NEW"; break;
        case NFCT_T_UPDATE: event->msg_type_str = "UPDATE"; break;
        case NFCT_T_DESTROY: event->msg_type_str = "DESTROY"; break;
        default: event->msg_type_str = "UNKNOWN"; break;
    }

    if (ed->l4proto == IPPROTO_TCP && ed->tcp_state != 255) {
        switch (ed->tcp_state) {
            case 0: event->state_str = "NONE"; break;
            case 1: event->state_str = "SYN_SENT"; break;
            case 2: event->state_str = "SYN_RECV"; break;
            case 3: event->state_str = "ESTABLISHED"; break;
            case 4: event->state_str = "FIN_WAIT"; break;
            case 5: event->state_str = "CLOSE_WAIT"; break;
            case 6: event->state_str = "LAST_ACK"; break;
            case 7: event->state_str = "TIME_WAIT"; break;
            case 8: event->state_str = "CLOSE"; break;
            default: event->state_str = "UNKNOWN"; break;
        }
    } else {
        event->state_str = "N/A";
    }

    if (hash_enabled) {
        char hash_input[256];
        snprintf(hash_input, sizeof(hash_input), "%s,%s,%s,%s,%u,%u,%s",
                 event->protocol_str, event->state_str, event->src_ip, event->dst_ip,
                 event->src_port, event->dst_port, event->msg_type_str);
        calculate_hash(hash_input, event->hash);
    } else {
        event->hash[0] = '\0';
    }

    event->timeout = ed->timeout;
    event->assured_str = (ed->status & IPS_ASSURED) ? "ASSURED" : "N/A";

    event->type_num = ed->type;
    event->state_num = (ed->l4proto == IPPROTO_TCP && ed->tcp_state != 255) ? ed->tcp_state : -1;
    event->proto_num = ed->l4proto;
}

// Conntrack event callback
static int event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct callback_data *cb_data = (struct callback_data *)data;
    struct event_data *ed = malloc(sizeof(*ed));
    if (!ed) {
        log_with_timestamp("[ERROR] Out of memory\n");
        return NFCT_CB_CONTINUE;
    }
    memset(ed, 0, sizeof(*ed));

    ed->type = type;
    ed->src_addr.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    ed->dst_addr.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    ed->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    ed->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;
    ed->l4proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    ed->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;
    ed->status = nfct_attr_is_set(ct, ATTR_STATUS) ? nfct_get_attr_u32(ct, ATTR_STATUS) : 0;
    if (ed->l4proto == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        ed->tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    } else {
        ed->tcp_state = 255;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ed->timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;

    if (cb_data->count_enabled) {
        ed->count = atomic_fetch_add(cb_data->event_counter, 1) + 1;
    } else {
        ed->count = 0;
    }

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ed->src_addr, src_ip_str, INET_ADDRSTRLEN);
    if (cb_data->src_range && !ip_in_range(src_ip_str, cb_data->src_range)) {
        free(ed);
        return NFCT_CB_CONTINUE;
    }

    if (!spsc_queue_enqueue(cb_data->queue, (void *)ed)) {
        free(ed);
        if (atomic_exchange(cb_data->overflow_flag, 1) == 0) {
            log_with_timestamp("[WARNING] SPSC queue overflow: events are being dropped!\n");
        }
    } else {
        if (atomic_exchange(cb_data->overflow_flag, 0) == 1) {
            log_with_timestamp("[INFO] SPSC queue returned to normal: events are no longer being dropped.\n");
        }
    }
    log_with_timestamp("[DEBUG] Successfully enqueued event\n");
    return NFCT_CB_CONTINUE;
}

// Connect to syslog server
static int connect_to_syslog(const char *host, const char *port_str) {
    struct addrinfo hints, *res, *rp;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        log_with_timestamp("[ERROR] getaddrinfo failed for %s:%s: %s\n", host, port_str, gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);

    if (sock == -1) {
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", host, port_str);
    } else {
        log_with_timestamp("[INFO] Successfully connected to syslog server at %s:%s\n", host, port_str);
    }

    return sock;
}

// Syslog message format
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data);
}

// Syslog thread
static void *syslog_thread(void *arg) {
    struct syslog_data *sdata = (struct syslog_data *)arg;
    char batch[MAX_MESSAGE_LEN * MIN_BATCH_SIZE] = "";
    int message_count = 0;
    struct timeval last_sent, now;
    gettimeofday(&last_sent, NULL);

    log_with_timestamp("[INFO] Syslog thread started. Waiting for events...\n");

    while (1) {
        gettimeofday(&now, NULL);
        long elapsed_us = (now.tv_sec - last_sent.tv_sec) * 1000000 + (now.tv_usec - last_sent.tv_usec);
        if (message_count > 0 && elapsed_us >= BATCH_TIMEOUT_US) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Timeout reached, sending %d messages\n", message_count);
            }
            goto send_batch;
        }

        struct event_data *ed_ptr;
        if (spsc_queue_dequeue(sdata->queue, (void **)&ed_ptr)) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Dequeued event data\n");
            }

            struct conn_event event = {0};
            extract_conn_event(ed_ptr, &event, sdata->hash_enabled);

            char data[1024] = {0};
            char *ptr = data;
            size_t remaining = sizeof(data);

            if (sdata->count_enabled) {
                ptr += snprintf(ptr, remaining, "%lld,", event.count);
                remaining -= (ptr - data);
            }

            ptr += snprintf(ptr, remaining, "%lld", event.timestamp_ns);
            remaining -= (ptr - data);

            if (sdata->hash_enabled || sdata->payload_enabled) {
                ptr += snprintf(ptr, remaining, ",");
                remaining -= (ptr - data);
            }

            if (sdata->hash_enabled) {
                ptr += snprintf(ptr, remaining, "%s", event.hash);
                remaining -= (ptr - data);
                if (sdata->payload_enabled) {
                    ptr += snprintf(ptr, remaining, ",");
                    remaining -= (ptr - data);
                }
            }

            if (sdata->payload_enabled) {
                ptr += snprintf(ptr, remaining, "%d,%d,%d,%s,%u,%s,%u",
                                event.type_num, event.state_num, event.proto_num,
                                event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                remaining -= (ptr - data);
            }

            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Formatted event: %s\n", data);
            }

            char syslog_msg[MAX_MESSAGE_LEN];
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, data);
            strncat(batch, syslog_msg, sizeof(batch) - strlen(batch) - 1);
            strncat(batch, "\n", sizeof(batch) - strlen(batch) - 1);
            message_count++;

            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Added message to batch, count: %d\n", message_count);
            }

            free(ed_ptr);
        } else {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] No data dequeued, sleeping...\n");
            }
            usleep(1000);
            continue;
        }

        if (message_count >= MIN_BATCH_SIZE) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Batch size reached, sending %d messages\n", message_count);
            }
            goto send_batch;
        }

    send_batch:
        if (sdata->debug_enabled) {
            log_with_timestamp("[DEBUG] Sending batch of %d messages: %s\n", message_count, batch);
        }
        if (sdata->syslog_fd < 0) {
            sdata->syslog_fd = connect_to_syslog(sdata->syslog_ip, SYSLOG_PORT);
            if (sdata->syslog_fd < 0) {
                log_with_timestamp("[ERROR] Failed to reconnect to syslog server\n");
                continue;
            }
        }
        size_t total_to_send = strlen(batch);
        size_t sent_so_far = 0;
        while (sent_so_far < total_to_send) {
            ssize_t sent = send(sdata->syslog_fd, batch + sent_so_far, total_to_send - sent_so_far, 0);
            if (sent > 0) {
                sent_so_far += sent;
            } else if (sent == 0) {
                log_with_timestamp("[ERROR] Connection closed while sending\n");
                close(sdata->syslog_fd);
                sdata->syslog_fd = -1;
                break;
            } else {
                if (errno == EINTR) continue;
                log_with_timestamp("[ERROR] Failed to send to syslog: %s\n", strerror(errno));
                if (errno == ENOTSOCK || errno == EBADF) {
                    close(sdata->syslog_fd);
                    sdata->syslog_fd = -1;
                }
                break;
            }
        }
        if (sent_so_far == total_to_send) {
            atomic_fetch_add(sdata->bytes_transferred, sent_so_far);
            log_with_timestamp("[INFO] Sent %zu bytes to syslog. Total transferred: %zu bytes\n",
                               sent_so_far, atomic_load(sdata->bytes_transferred));
            batch[0] = '\0';
            message_count = 0;
            gettimeofday(&last_sent, NULL);
        } else {
            // Partial send or failure
            char *p = batch;
            int num_complete = 0;
            size_t i;
            for (i = 0; i < sent_so_far && p[i] != '\0'; i++) {
                if (p[i] == '\n') num_complete++;
            }
            message_count -= num_complete;
            size_t unsent_len = strlen(batch + sent_so_far);
            memmove(batch, batch + sent_so_far, unsent_len + 1);
        }
    }
    return NULL;
}

// Kill running daemons
static void kill_all_daemons() {
    pid_t current_pid = getpid();
    FILE *fp = popen("pidof conntrack_logger", "r");
    if (!fp) {
        log_with_timestamp("Failed to run pidof\n");
        return;
    }
    char pid_str[16];
    while (fscanf(fp, "%s", pid_str) == 1) {
        pid_t pid = atoi(pid_str);
        if (pid != current_pid) {
            if (kill(pid, SIGTERM) == -1) {
                log_with_timestamp("Failed to kill process %d: %s\n", pid, strerror(errno));
            }
        }
    }
    pclose(fp);
}

// Signal handler
static void signal_handler(int sig) {
    log_with_timestamp("[INFO] Received signal %d, shutting down\n", sig);
    exit(0);
}

// Main function
int main(int argc, char *argv[]) {
    struct config cfg;
    if (parse_config(argc, argv, &cfg)) return 1;

    global_debug_enabled = cfg.debug_enabled;

    if (!cfg.kill_daemons && !cfg.hash_enabled && !cfg.payload_enabled) {
        log_with_timestamp("Error: At least one of -H or -P must be specified.\n");
        print_help(argv[0]);
        return 1;
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    if (cfg.kill_daemons) {
        kill_all_daemons();
        log_with_timestamp("Killed all running daemons\n");
        return 0;
    }

    if (getuid() != 0) {
        log_with_timestamp("This program requires root privileges. Please run with sudo.\n");
        return 1;
    }

    if (cfg.daemonize) {
        if (daemon(0, 0) < 0) {
            log_with_timestamp("Failed to daemonize: %s\n", strerror(errno));
            return 1;
        }
        int logfd = open(LOGFILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd < 0) {
            perror("Failed to open log file for daemon output");
            return 1;
        }
        if (dup2(logfd, STDOUT_FILENO) < 0 || dup2(logfd, STDERR_FILENO) < 0) {
            perror("Failed to redirect stdout/stderr to log file");
            close(logfd);
            return 1;
        }
        close(logfd);
        log_with_timestamp("[INFO] conntrack_logger daemon started, output redirected to %s\n", LOGFILE_PATH);
    }

    int syslog_fd = connect_to_syslog(cfg.syslog_ip, SYSLOG_PORT);
    if (syslog_fd < 0) {
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", cfg.syslog_ip, SYSLOG_PORT);
        return 1;
    }

    spsc_queue_t queue;
    spsc_queue_init(&queue, SPSC_QUEUE_CAPACITY);

    atomic_size_t bytes_transferred = 0;
    atomic_int overflow_flag = 0;

    struct syslog_data sdata = {
        .queue = &queue,
        .syslog_ip = cfg.syslog_ip,
        .syslog_fd = syslog_fd,
        .machine_name = cfg.machine_name,
        .count_enabled = cfg.count_enabled,
        .debug_enabled = cfg.debug_enabled,
        .hash_enabled = cfg.hash_enabled,
        .payload_enabled = cfg.payload_enabled,
        .bytes_transferred = &bytes_transferred,
        .overflow_flag = &overflow_flag
    };
    pthread_t syslog_tid;
    if (pthread_create(&syslog_tid, NULL, syslog_thread, &sdata) != 0) {
        log_with_timestamp("[ERROR] Failed to create syslog thread\n");
        close(syslog_fd);
        spsc_queue_destroy(&queue);
        return 1;
    }
    pthread_detach(syslog_tid);

    struct callback_data cb_data = {
        .queue = &queue,
        .overflow_flag = &overflow_flag,
        .count_enabled = cfg.count_enabled,
        .hash_enabled = cfg.hash_enabled,
        .payload_enabled = cfg.payload_enabled,
        .event_counter = &event_counter,
        .src_range = cfg.src_range
    };
    struct nfct_handle *cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                        NF_NETLINK_CONNTRACK_UPDATE |
                                        NF_NETLINK_CONNTRACK_DESTROY);
    if (!cth) {
        log_with_timestamp("[ERROR] Failed to open conntrack handle: %s\n", strerror(errno));
        close(syslog_fd);
        spsc_queue_destroy(&queue);
        return 1;
    }

    nfct_callback_register(cth, NFCT_T_ALL, event_cb, &cb_data);
    log_with_timestamp("[INFO] Starting to catch conntrack events\n");
    if (nfct_catch(cth) < 0) {
        log_with_timestamp("[ERROR] Failed to catch conntrack events: %s\n", strerror(errno));
    }

    nfct_close(cth);
    close(syslog_fd);
    spsc_queue_destroy(&queue);
    return 0;
}
