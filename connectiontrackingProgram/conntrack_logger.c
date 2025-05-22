/*
 * 
 * 
 * Features:
 * - Three threads: main (Netfilter event collection), formatting, syslog sending.
 * - Two SPSC queues: event_queue (raw events, main->formatting), syslog_queue (formatted events, formatting->syslog).
 * - Handles SIGINT/SIGTERM gracefully, unblocking all threads for prompt exit.
 * - Batches syslog messages and sends in bulk; lost batches are retried on next send.
 * - Argument interface and output format matches legacy conntrack_logger.c.
 * - Extensive debug messages and explicit queue-overflow diagnostics.
 * 
 * Build: gcc -O2 -Wall -pthread -lblake3 -lnetfilter_conntrack -o conntrack_logger_threaded_debug conntrack_logger_threaded_debug.c
 */

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

// ----------- CONFIGURABLE CONSTANTS -----------------
#define DEFAULT_QUEUE_SIZE 20480    // Increased from 1024 to 16384 for burst tolerance
#define MIN_BATCH_SIZE 10
#define MAX_MESSAGE_LEN 1024
#define BATCH_TIMEOUT_US 1000000    // 1 second
#define SYSLOG_PORT "514"
#define LOGFILE_PATH "/var/log/conntrack_logger.log"

// ----------- SPSC QUEUE IMPLEMENTATION -------------
typedef struct {
    void **items;
    size_t head;
    size_t tail;
    size_t capacity;
} spsc_queue_t;

// Create a new SPSC queue with given capacity
spsc_queue_t* spsc_queue_init(size_t capacity) {
    spsc_queue_t *q = malloc(sizeof(spsc_queue_t));
    if (!q) return NULL;
    q->items = malloc(sizeof(void*) * capacity);
    if (!q->items) { free(q); return NULL; }
    q->head = 0;
    q->tail = 0;
    q->capacity = capacity;
    return q;
}

// Enqueue an item (returns 0 on success, -1 if queue full)
int spsc_queue_push(spsc_queue_t *q, void *item) {
    size_t next_head = (q->head + 1) % q->capacity;
    if (next_head == q->tail) return -1; // Queue full
    q->items[q->head] = item;
    q->head = next_head;
    return 0;
}

// Dequeue an item (returns 1 on success, 0 if empty)
int spsc_queue_try_pop(spsc_queue_t *q, void **item) {
    if (q->tail == q->head) return 0; // Queue empty
    *item = q->items[q->tail];
    q->tail = (q->tail + 1) % q->capacity;
    return 1;
}

// Free all memory used by the queue
void spsc_queue_destroy(spsc_queue_t *q) {
    free(q->items);
    free(q);
}

// ----------- CONFIGURATION STRUCT -------------------
typedef struct {
    char *syslog_ip;
    char *machine_name;
    int daemonize;
    int kill_daemons;
    int count_enabled;
    int debug_enabled;
    int hash_enabled;
    int payload_enabled;
    char *src_range;
} config_t;

// ----------- EVENT STRUCTURES -----------------------
typedef struct {
    long long timestamp_ns;
    struct nf_conntrack *ct;
    enum nf_conntrack_msg_type type;
    long long count;
} event_data_t;

typedef struct {
    long long count;
    long long timestamp_ns;
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port;
    char protocol_str[16];
    char msg_type_str[8];
    uint32_t timeout;
    char state_str[16];
    char assured_str[8];
    char hash[17];
    int type_num;
    int state_num;
    int proto_num;
} conn_event_t;

// ----------- APPLICATION CONTEXT --------------------
typedef struct {
    spsc_queue_t *event_queue;
    spsc_queue_t *syslog_queue;
    config_t *cfg;
} app_context_t;

typedef struct {
    spsc_queue_t *queue;
    int debug_enabled;
    char *machine_name;
    char *syslog_ip;
    int syslog_fd;
    atomic_size_t bytes_transferred;
} syslog_data_t;

// ----------- GLOBALS --------------------------------
static int global_debug_enabled = 0;
static atomic_llong event_counter = 0;
volatile sig_atomic_t shutdown_flag = 0;
struct nfct_handle *g_nfct_handle = NULL; // needed for signal-safe shutdown

// ----------- LOGGING --------------------------------
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

// ----------- SIGNAL HANDLING ------------------------
// Only set a flag; don't call unsafe functions here!
void signal_handler(int sig) {
    static int already_logged = 0;
    if (!already_logged) {
        log_with_timestamp("[INFO] Received signal %d, shutting down\n", sig);
        already_logged = 1;
    }
    shutdown_flag = 1;
    // Do NOT call nfct_close here -- not async-signal-safe!
}


// ----------- HELP MESSAGE ---------------------------
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

// ----------- ARGUMENT PARSING -----------------------
static int parse_config(int argc, char *argv[], config_t *cfg) {
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

    if (!cfg->kill_daemons && !cfg->hash_enabled && !cfg->payload_enabled) {
        log_with_timestamp("Error: At least one of -H or -P must be specified.\n");
        print_help(argv[0]);
        return 1;
    }

    return 0;
}

// ----------- DAEMON KILL UTILITY --------------------
static void kill_all_daemons() {
    pid_t current_pid = getpid();
    FILE *fp = popen("pidof conntrack_logger", "r");
    if (!fp) {
        log_with_timestamp("[ERROR] Failed to run pidof\n");
        return;
    }
    char pid_str[16];
    while (fscanf(fp, "%s", pid_str) == 1) {
        pid_t pid = atoi(pid_str);
        if (pid != current_pid) {
            if (kill(pid, SIGTERM) == -1) {
                log_with_timestamp("[ERROR] Failed to kill process %d: %s\n", pid, strerror(errno));
            } else {
                log_with_timestamp("[INFO] Killed process %d\n", pid);
            }
        }
    }
    pclose(fp);
}

// ----------- UTILITY: IP IN RANGE -------------------
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

// ----------- BLAKE3 HASHING FOR EVENT SIGNATURE -----
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

// ----------- EXTRACT DETAILED EVENT INFO ------------
static void extract_conn_event(
    struct nf_conntrack *ct, enum nf_conntrack_msg_type type,
    conn_event_t *event, int count_enabled, int hash_enabled,
    int payload_enabled, long long count, long long timestamp_ns
) {
    event->count = count_enabled ? count : 0;
    event->timestamp_ns = timestamp_ns; // Ensure timestamp is carried forward

    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    inet_ntop(AF_INET, &src_addr, event->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, event->dst_ip, INET_ADDRSTRLEN);

    event->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    event->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;

    if (payload_enabled) {
        event->type_num = type;
        event->proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO);
        if (event->proto_num == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
            event->state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        } else {
            event->state_num = -1;
        }
    } else {
        event->type_num = 0;
        event->state_num = -1;
        event->proto_num = 0;
    }

    if (hash_enabled || payload_enabled) {
        if (event->proto_num == 0) event->proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO);
        if (event->proto_num == IPPROTO_TCP) strcpy(event->protocol_str, "tcp");
        else if (event->proto_num == IPPROTO_UDP) strcpy(event->protocol_str, "udp");
        else snprintf(event->protocol_str, sizeof(event->protocol_str), "proto %d", event->proto_num);

        switch (type) {
            case NFCT_T_NEW:     strcpy(event->msg_type_str, "NEW");     break;
            case NFCT_T_UPDATE:  strcpy(event->msg_type_str, "UPDATE");  break;
            case NFCT_T_DESTROY: strcpy(event->msg_type_str, "DESTROY"); break;
            default:             strcpy(event->msg_type_str, "UNKNOWN"); break;
        }

        if (event->state_num < 0 && event->proto_num == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
            event->state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        }
        if (event->state_num >= 0) {
            switch (event->state_num) {
                case 0: strcpy(event->state_str, "NONE"); break;
                case 1: strcpy(event->state_str, "SYN_SENT"); break;
                case 2: strcpy(event->state_str, "SYN_RECV"); break;
                case 3: strcpy(event->state_str, "ESTABLISHED"); break;
                case 4: strcpy(event->state_str, "FIN_WAIT"); break;
                case 5: strcpy(event->state_str, "CLOSE_WAIT"); break;
                case 6: strcpy(event->state_str, "LAST_ACK"); break;
                case 7: strcpy(event->state_str, "TIME_WAIT"); break;
                case 8: strcpy(event->state_str, "CLOSE"); break;
                default: strcpy(event->state_str, "UNKNOWN"); break;
            }
        } else {
            strcpy(event->state_str, "N/A");
        }
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

    event->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;
    strcpy(event->assured_str, "N/A");
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) strcpy(event->assured_str, "ASSURED");
    }
}

// ----------- CONNTRACK CALLBACK ---------------------
// Called from main thread for each conntrack event
static atomic_int event_overflow_reported = 0; // For queue overflow warning throttling

static int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    app_context_t *ctx = (app_context_t *)data;

    // Filter by source IP range (if specified)
    if (ctx->cfg->src_range) {
        struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        if (!ip_in_range(src_ip, ctx->cfg->src_range)) {
            if (ctx->cfg->debug_enabled)
                log_with_timestamp("[DEBUG] Event ignored: src_ip %s not in range %s\n", src_ip, ctx->cfg->src_range);
            return NFCT_CB_CONTINUE;
        }
    }

    // Allocate and populate event_data_t
    event_data_t *event = malloc(sizeof(event_data_t));
    if (!event) {
        log_with_timestamp("[ERROR] Failed to allocate event_data_t\n");
        return NFCT_CB_CONTINUE;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    event->timestamp_ns = (uint64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    event->ct = nfct_clone(ct);
    if (!event->ct) {
        log_with_timestamp("[ERROR] Failed to clone conntrack\n");
        free(event);
        return NFCT_CB_CONTINUE;
    }
    event->type = type;
    event->count = ctx->cfg->count_enabled ? atomic_fetch_add(&event_counter, 1) + 1 : 0;

    // Attempt to enqueue event in event_queue
    if (spsc_queue_push(ctx->event_queue, event) != 0) {
        if (atomic_exchange(&event_overflow_reported, 1) == 0) {
            log_with_timestamp("[WARNING] event_queue OVERFLOW: events are being dropped!\n");
        }
        nfct_destroy(event->ct);
        free(event);
    } else {
        // Reset overflow report if queue recovers
        atomic_store(&event_overflow_reported, 0);
        if (ctx->cfg->debug_enabled)
            log_with_timestamp("[DEBUG] Event enqueued to event_queue\n");
    }

    return NFCT_CB_CONTINUE;
}

// ----------- SYSLOG CONNECTION ----------------------
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

// ----------- SYSLOG MESSAGE FORMAT ------------------
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data);
}

// ----------- FORMATTING THREAD ----------------------
// Converts raw events to formatted string and enqueues to syslog_queue
void* formatting_thread(void* arg) {
    app_context_t *ctx = (app_context_t *)arg;
    static atomic_int syslog_overflow_reported = 0;

    while (!shutdown_flag) {
        void *item;
        if (spsc_queue_try_pop(ctx->event_queue, &item)) {
            event_data_t *event_data = (event_data_t *)item;
            conn_event_t event;
            memset(&event, 0, sizeof(conn_event_t));

            extract_conn_event(
                event_data->ct, event_data->type, &event,
                ctx->cfg->count_enabled, ctx->cfg->hash_enabled,
                ctx->cfg->payload_enabled, event_data->count, event_data->timestamp_ns
            );

            char buffer[MAX_MESSAGE_LEN] = {0};
            char *ptr = buffer;
            size_t remaining = sizeof(buffer);

            if (ctx->cfg->count_enabled) {
                ptr += snprintf(ptr, remaining, "%lld,", event.count);
                remaining -= (ptr - buffer);
            }
            ptr += snprintf(ptr, remaining, "%lld", event.timestamp_ns);
            remaining -= (ptr - buffer);

            if (ctx->cfg->hash_enabled || ctx->cfg->payload_enabled) {
                ptr += snprintf(ptr, remaining, ",");
                remaining -= (ptr - buffer);
            }
            if (ctx->cfg->hash_enabled) {
                ptr += snprintf(ptr, remaining, "%s", event.hash);
                remaining -= (ptr - buffer);
                if (ctx->cfg->payload_enabled) {
                    ptr += snprintf(ptr, remaining, ",");
                    remaining -= (ptr - buffer);
                }
            }
            if (ctx->cfg->payload_enabled) {
                ptr += snprintf(ptr, remaining, "%d,%d,%d,%s,%u,%s,%u",
                                event.type_num, event.state_num, event.proto_num,
                                event.src_ip, event.src_port, event.dst_ip, event.dst_port);
                remaining -= (ptr - buffer);
            }

            if (ctx->cfg->debug_enabled) {
                log_with_timestamp("[DEBUG] Formatting thread: Formatted event: %s\n", buffer);
            }

            // Enqueue to syslog_queue; report overflow only once per burst
            char *formatted_msg = strdup(buffer);
            if (formatted_msg) {
                if (spsc_queue_push(ctx->syslog_queue, formatted_msg) != 0) {
                    if (atomic_exchange(&syslog_overflow_reported, 1) == 0) {
                        log_with_timestamp("[WARNING] syslog_queue OVERFLOW: formatted messages are being dropped!\n");
                    }
                    free(formatted_msg);
                } else {
                    atomic_store(&syslog_overflow_reported, 0);
                    if (ctx->cfg->debug_enabled)
                        log_with_timestamp("[DEBUG] Formatting thread: Message enqueued to syslog_queue\n");
                }
            } else {
                log_with_timestamp("[ERROR] Formatting thread: Failed to allocate formatted message\n");
            }

            nfct_destroy(event_data->ct);
            free(event_data);
        } else {
            if (ctx->cfg->debug_enabled)
                log_with_timestamp("[DEBUG] Formatting thread: No data dequeued, sleeping...\n");
            usleep(1000);
        }
    }
    log_with_timestamp("[INFO] Formatting thread exiting by shutdown request\n");
    return NULL;
}

// ----------- SYSLOG THREAD --------------------------
// Batches and sends log messages; if send fails, retries lost batch on next send
void* syslog_thread(void* arg) {
    syslog_data_t *sdata = (syslog_data_t *)arg;
    char *buffer = NULL;
    char batch[MAX_MESSAGE_LEN * MIN_BATCH_SIZE] = "";
    char *lost_batch = NULL;
    int message_count = 0;
    struct timeval last_sent, now;
    gettimeofday(&last_sent, NULL);

    log_with_timestamp("[INFO] Syslog thread started. Waiting for events...\n");

    while (!shutdown_flag) {
        gettimeofday(&now, NULL);
        long elapsed_us = (now.tv_sec - last_sent.tv_sec) * 1000000 + (now.tv_usec - last_sent.tv_usec);

        // Send batch due to timeout
        if (message_count > 0 && elapsed_us >= BATCH_TIMEOUT_US) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Syslog thread: Batch timeout reached, sending %d messages\n", message_count);
            }
            goto send_batch;
        }

        // Try to dequeue a formatted message
        if (spsc_queue_try_pop(sdata->queue, (void**)&buffer)) {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Syslog thread: Dequeued buffer: %s\n", buffer);
            }

            char syslog_msg[MAX_MESSAGE_LEN];
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, buffer);
            strncat(batch, syslog_msg, sizeof(batch) - strlen(batch) - 1);
            strncat(batch, "\n", sizeof(batch) - strlen(batch) - 1);
            message_count++;

            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Syslog thread: Added message to batch, count: %d\n", message_count);
            }

            free(buffer);
            buffer = NULL;

            if (message_count >= MIN_BATCH_SIZE) {
                if (sdata->debug_enabled) {
                    log_with_timestamp("[DEBUG] Syslog thread: Batch size reached, sending %d messages\n", message_count);
                }
                goto send_batch;
            }
        } else {
            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Syslog thread: No data dequeued, sleeping...\n");
            }
            usleep(1000);
            continue;
        }
        continue;

    send_batch: ;
        char big_batch[MAX_MESSAGE_LEN * MIN_BATCH_SIZE * 2] = "";
        if (lost_batch) {
            strncat(big_batch, lost_batch, sizeof(big_batch) - strlen(big_batch) - 1);
        }
        strncat(big_batch, batch, sizeof(big_batch) - strlen(big_batch) - 1);

        if (sdata->debug_enabled) {
            log_with_timestamp("[DEBUG] Syslog thread: Sending batch+lost_batch (%zu bytes)", strlen(big_batch));
        }
        if (sdata->syslog_fd < 0) {
            sdata->syslog_fd = connect_to_syslog(sdata->syslog_ip, SYSLOG_PORT);
        }
        int sent_ok = 0;
        if (sdata->syslog_fd >= 0) {
            ssize_t sent = send(sdata->syslog_fd, big_batch, strlen(big_batch), 0);
            if (sent > 0) {
                atomic_fetch_add(&sdata->bytes_transferred, sent);
                log_with_timestamp("[INFO] Syslog thread: Sent %zd bytes to syslog. Total transferred: %zu bytes\n",
                                   sent, atomic_load(&sdata->bytes_transferred));
                sent_ok = 1;
            } else {
                log_with_timestamp("[ERROR] Syslog thread: Failed to send to syslog: %s\n", strerror(errno));
                close(sdata->syslog_fd);
                sdata->syslog_fd = -1;
            }
        }
        free(lost_batch);
        if (sent_ok) {
            lost_batch = NULL;
        } else {
            lost_batch = strdup(big_batch);
            if (!lost_batch) log_with_timestamp("[ERROR] Syslog thread: Failed to save lost batch\n");
        }
        batch[0] = '\0';
        message_count = 0;
        gettimeofday(&last_sent, NULL);
    }
    if (lost_batch) free(lost_batch);
    log_with_timestamp("[INFO] Syslog thread exiting by shutdown request\n");
    return NULL;
}

// ----------- MAIN FUNCTION --------------------------
int main(int argc, char *argv[]) {
    config_t cfg;
    if (parse_config(argc, argv, &cfg) != 0) return 1;

    if (cfg.kill_daemons) {
        kill_all_daemons();
        return 0;
    }

    if (cfg.daemonize) {
        if (daemon(0, 0) < 0) {
            log_with_timestamp("[ERROR] Failed to daemonize: %s\n", strerror(errno));
            return 1;
        }
        int logfd = open(LOGFILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd < 0) {
            perror("Failed to open log file");
            return 1;
        }
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);
    }

    global_debug_enabled = cfg.debug_enabled;

    // Initialize SPSC queues (large enough for burst tolerance)
    spsc_queue_t *event_queue = spsc_queue_init(DEFAULT_QUEUE_SIZE);
    if (!event_queue) {
        log_with_timestamp("[ERROR] Failed to initialize event_queue\n");
        return 1;
    }
    spsc_queue_t *syslog_queue = spsc_queue_init(DEFAULT_QUEUE_SIZE);
    if (!syslog_queue) {
        log_with_timestamp("[ERROR] Failed to initialize syslog_queue\n");
        spsc_queue_destroy(event_queue);
        return 1;
    }

    app_context_t ctx = {
        .event_queue = event_queue,
        .syslog_queue = syslog_queue,
        .cfg = &cfg
    };

    pthread_t formatting_tid;
    if (pthread_create(&formatting_tid, NULL, formatting_thread, &ctx) != 0) {
        log_with_timestamp("[ERROR] Failed to create formatting thread\n");
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    syslog_data_t sdata = {
        .queue = syslog_queue,
        .debug_enabled = cfg.debug_enabled,
        .machine_name = cfg.machine_name,
        .syslog_ip = cfg.syslog_ip,
        .syslog_fd = -1,
        .bytes_transferred = 0
    };

    pthread_t syslog_tid;
    if (pthread_create(&syslog_tid, NULL, syslog_thread, &sdata) != 0) {
        log_with_timestamp("[ERROR] Failed to create syslog thread\n");
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    // Signal handling for shutdown
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    g_nfct_handle = nfct_open(NFNL_SUBSYS_CTNETLINK,
                              NFNLGRP_CONNTRACK_NEW |
                              NFNLGRP_CONNTRACK_UPDATE |
                              NFNLGRP_CONNTRACK_DESTROY);
    if (!g_nfct_handle) {
        log_with_timestamp("[ERROR] Failed to open nfct handle\n");
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }
    nfct_callback_register(g_nfct_handle, NFCT_T_ALL, cb, &ctx);

    // --- Set nfct fd to non-blocking mode ---
    int fd = nfct_fd(g_nfct_handle);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_with_timestamp("[ERROR] Failed to set O_NONBLOCK on nfct fd: %s\n", strerror(errno));
        nfct_close(g_nfct_handle);
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    log_with_timestamp("[INFO] Starting to catch conntrack events\n");

    // --- Non-blocking event loop, responsive to shutdown ---
    while (!shutdown_flag) {
        int ret = nfct_catch(g_nfct_handle);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000); // Sleep 100ms
                continue;
            }
            if (errno == EINTR) continue;
            log_with_timestamp("[ERROR] nfct_catch failed: %s\n", strerror(errno));
            break;
        }
    }

    // --- Cleanup ---
    log_with_timestamp("[INFO] Exiting, cleaning up...\n");

    if (g_nfct_handle) {
        nfct_close(g_nfct_handle);
        g_nfct_handle = NULL;
    }

    pthread_join(formatting_tid, NULL);
    pthread_join(syslog_tid, NULL);

    spsc_queue_destroy(event_queue);
    spsc_queue_destroy(syslog_queue);

    if (sdata.syslog_fd >= 0) close(sdata.syslog_fd);

    log_with_timestamp("[INFO] Exiting, final close\n");

    return 0;
}
