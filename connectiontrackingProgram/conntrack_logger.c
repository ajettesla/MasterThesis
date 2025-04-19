#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <openssl/sha.h>
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

// Replace with your SPSC queue implementation header
#include "spsc_queue.h"

#define MAX_MESSAGE_LEN 2048
#define SYSLOG_PORT "514"
#define MIN_BATCH_SIZE 5
#define BATCH_TIMEOUT_US 1000000  // 1 second timeout for batching
#define LOGFILE_PATH "/var/log/conntrack_logger.log"  // Change as needed

/** Configuration structure for command-line options */
struct config {
    char *syslog_ip;
    char *machine_name;
    int daemonize;
    int kill_daemons;
    int count_enabled;
    int debug_enabled;
    int hash_enabled;  // New field for hash option
};

/** Structure for connection event data */
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
    const char *state_str;
    const char *assured_str;
    char hash[65];  // New field for hash
};

/** Structure for event callback data */
struct callback_data {
    spsc_queue_t *queue;
    atomic_int *overflow_flag;
    int count_enabled;
    int hash_enabled;  // New field for hash option
    atomic_llong *event_counter;
};

/** Structure for syslog thread data */
struct syslog_data {
    spsc_queue_t *queue;
    char *syslog_ip;
    int syslog_fd;
    char *machine_name;
    int count_enabled;
    int debug_enabled;
    int hash_enabled;  // New field for hash option
    atomic_size_t *bytes_transferred;
    atomic_int *overflow_flag;
};

// Global debug flag for logging
static int global_debug_enabled = 0;

/** Log messages with timestamps, respecting debug toggle */
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

/** Display help message */
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
    printf("  -H, --hash                Include SHA256 hash in log messages (optional)\n");
}

/** Parse command-line arguments */
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

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:DH", long_options, NULL)) != -1) {
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

/** Compute SHA256 hash of a string */
static void calculate_sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

/** Extract connection event details from nf_conntrack */
static void extract_conn_event(struct nf_conntrack *ct, enum nf_conntrack_msg_type type, struct conn_event *event, int count_enabled, int hash_enabled, atomic_llong *event_counter) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    event->timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;

    if (count_enabled) {
        event->count = atomic_fetch_add(event_counter, 1) + 1;
    } else {
        event->count = 0;
    }

    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    inet_ntop(AF_INET, &src_addr, event->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, event->dst_ip, INET_ADDRSTRLEN);

    event->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    event->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    if (proto == IPPROTO_TCP) strcpy(event->protocol_str, "tcp");
    else if (proto == IPPROTO_UDP) strcpy(event->protocol_str, "udp");
    else snprintf(event->protocol_str, sizeof(event->protocol_str), "proto %u", proto);

    switch (type) {
        case NFCT_T_NEW:     event->msg_type_str = "NEW";     break;
        case NFCT_T_UPDATE:  event->msg_type_str = "UPDATE";  break;
        case NFCT_T_DESTROY: event->msg_type_str = "DESTROY"; break;
        default:             event->msg_type_str = "UNKNOWN"; break;
    }

    event->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;

    event->state_str = "N/A";
    if (proto == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        uint8_t tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        switch (tcp_state) {
            case 0: event->state_str = "NONE"; break;
            case 1: event->state_str = "SYN_SENT"; break;
            case 2: event->state_str = "SYN_RECV"; break;
            case 3: event: event->state_str = "ESTABLISHED"; break;
            case 4: event->state_str = "FIN_WAIT"; break;
            case 5: event->state_str = "CLOSE_WAIT"; break;
            case 6: event->state_str = "LAST_ACK"; break;
            case 7: event->state_str = "TIME_WAIT"; break;
            case 8: event->state_str = "CLOSE"; break;
            default: event->state_str = "UNKNOWN"; break;
        }
    }

    event->assured_str = "N/A";
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) event->assured_str = "ASSURED";
    }

    if (hash_enabled) {
        char hash_input[256];
        snprintf(hash_input, sizeof(hash_input), "%s%s%u%u%s", event->src_ip, event->dst_ip, event->src_port, event->dst_port, event->protocol_str);
        calculate_sha256(hash_input, event->hash);
    } else {
        event->hash[0] = '\0';
    }
}

/** Callback for connection tracking events */
static int event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct callback_data *cb_data = (struct callback_data *)data;
    struct conn_event event = {0};
    extract_conn_event(ct, type, &event, cb_data->count_enabled, cb_data->hash_enabled, cb_data->event_counter);
    char buffer[1024] = {0};

    if (cb_data->count_enabled) {
        if (cb_data->hash_enabled) {
            snprintf(buffer, sizeof(buffer),
                "%lld,%lld,%s,%u,%s,%u,%s,%s,%u,%s,%s,%s",
                event.count, event.timestamp_ns,
                event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.protocol_str, event.msg_type_str, event.timeout,
                event.state_str, event.assured_str, event.hash);
        } else {
            snprintf(buffer, sizeof(buffer),
                "%lld,%lld,%s,%u,%s,%u,%s,%s,%u,%s,%s",
                event.count, event.timestamp_ns,
                event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.protocol_str, event.msg_type_str, event.timeout,
                event.state_str, event.assured_str);
        }
    } else {
        if (cb_data->hash_enabled) {
            snprintf(buffer, sizeof(buffer),
                "%lld,%s,%u,%s,%u,%s,%s,%u,%s,%s,%s",
                event.timestamp_ns,
                event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.protocol_str, event.msg_type_str, event.timeout,
                event.state_str, event.assured_str, event.hash);
        } else {
            snprintf(buffer, sizeof(buffer),
                "%lld,%s,%u,%s,%u,%s,%s,%u,%s,%s",
                event.timestamp_ns,
                event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.protocol_str, event.msg_type_str, event.timeout,
                event.state_str, event.assured_str);
        }
    }

    log_with_timestamp("[DEBUG] Captured conntrack event: %s\n", buffer);

    if (!spsc_queue_enqueue(cb_data->queue, buffer)) {
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

/** Establish TCP connection to syslog server */
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

/** Format a syslog message */
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data);
}

/** Syslog thread to batch and send events */
static void *syslog_thread(void *arg) {
    struct syslog_data *sdata = (struct syslog_data *)arg;
    char *buffer = NULL;
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

        if (spsc_queue_dequeue(sdata->queue, &buffer)) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Dequeued buffer: %s\n", buffer);
            }

            long long count, timestamp_ns;
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            unsigned int src_port, dst_port;
            char protocol_str[16], msg_type_str[16], state_str[16], assured_str[16], hash[65];
            unsigned int timeout;
            int parsed;

            if (sdata->count_enabled) {
                if (sdata->hash_enabled) {
                    parsed = sscanf(buffer,
                        "%lld,%lld,%15[^,],%u,%15[^,],%u,%15[^,],%15[^,],%u,%15[^,],%15[^,],%64s",
                        &count, &timestamp_ns, src_ip, &src_port, dst_ip, &dst_port,
                        protocol_str, msg_type_str, &timeout, state_str, assured_str, hash);
                    if (parsed != 12) {
                        log_with_timestamp("[ERROR] Failed to parse buffer with count and hash: %s\n", buffer);
                        free(buffer);
                        continue;
                    }
                } else {
                    parsed = sscanf(buffer,
                        "%lld,%lld,%15[^,],%u,%15[^,],%u,%15[^,],%15[^,],%u,%15[^,],%15[^,]",
                        &count, &timestamp_ns, src_ip, &src_port, dst_ip, &dst_port,
                        protocol_str, msg_type_str, &timeout, state_str, assured_str);
                    if (parsed != 11) {
                        log_with_timestamp("[ERROR] Failed to parse buffer with count: %s\n", buffer);
                        free(buffer);
                        continue;
                    }
                }
            } else {
                if (sdata->hash_enabled) {
                    parsed = sscanf(buffer,
                        "%lld,%15[^,],%u,%15[^,],%u,%15[^,],%15[^,],%u,%15[^,],%15[^,],%64s",
                        &timestamp_ns, src_ip, &src_port, dst_ip, &dst_port,
                        protocol_str, msg_type_str, &timeout, state_str, assured_str, hash);
                    if (parsed != 11) {
                        log_with_timestamp("[ERROR] Failed to parse buffer with hash: %s\n", buffer);
                        free(buffer);
                        continue;
                    }
                } else {
                    parsed = sscanf(buffer,
                        "%lld,%15[^,],%u,%15[^,],%u,%15[^,],%15[^,],%u,%15[^,],%15[^,]",
                        &timestamp_ns, src_ip, &src_port, dst_ip, &dst_port,
                        protocol_str, msg_type_str, &timeout, state_str, assured_str);
                    if (parsed != 10) {
                        log_with_timestamp("[ERROR] Failed to parse buffer: %s\n", buffer);
                        free(buffer);
                        continue;
                    }
                }
            }

            char syslog_msg[MAX_MESSAGE_LEN];
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, buffer);
            strncat(batch, syslog_msg, sizeof(batch) - strlen(batch) - 1);
            strncat(batch, "\n", sizeof(batch) - strlen(batch) - 1);
            message_count++;

            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Added message to batch, count: %d\n", message_count);
            }

            free(buffer);
            buffer = NULL;
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
        send_batch:
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Sending batch of %d messages: %s\n", message_count, batch);
            }
            if (sdata->syslog_fd < 0) {
                sdata->syslog_fd = connect_to_syslog(sdata->syslog_ip, SYSLOG_PORT);
                if (sdata->syslog_fd < 0) {
                    log_with_timestamp("[ERROR] Failed to reconnect to syslog server\n");
                    batch[0] = '\0';
                    message_count = 0;
                    gettimeofday(&last_sent, NULL);
                    continue;
                }
            }
            ssize_t sent = send(sdata->syslog_fd, batch, strlen(batch), 0);
            if (sent > 0) {
                atomic_fetch_add(sdata->bytes_transferred, sent);
                log_with_timestamp("[INFO] Sent %zd bytes to syslog. Total transferred: %zu bytes\n",
                                   sent, atomic_load(sdata->bytes_transferred));
            } else {
                log_with_timestamp("[ERROR] Failed to send to syslog: %s\n", strerror(errno));
                close(sdata->syslog_fd);
                sdata->syslog_fd = -1;
            }
            batch[0] = '\0';
            message_count = 0;
            gettimeofday(&last_sent, NULL);
        }
    }
    return NULL;
}

/** Kill all running instances of the program */
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

/** Main function */
int main(int argc, char *argv[]) {
    struct config cfg;
    if (parse_config(argc, argv, &cfg)) return 1;

    global_debug_enabled = cfg.debug_enabled;

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
        .event_counter = &event_counter
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
