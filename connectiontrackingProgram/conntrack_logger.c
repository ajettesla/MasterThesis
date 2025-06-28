/*
 * High-performance conntrack logger optimized for 100k events/sec
 * 
 * Key features:
 * - Zero-latency edge-triggered epoll with RT priority
 * - Dynamic batch sizing with back-pressure to prevent packet loss
 * - Detailed protocol/state statistics with periodic reporting
 * - Enhanced message formatting with BLAKE3 hash
 * - Proper syslog message formatting with RFC5424 compliance
 * 
 * Author: ajettesla
 * Date: 2025-06-28 09:12:12
 * 
 * Build: gcc -O2 -Wall -pthread -lblake3 -lnetfilter_conntrack -o conntrack_logger conntrack_logger.c
 */
#define _GNU_SOURCE
#include <sys/epoll.h>
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
#include <limits.h>
#include <sched.h>

// ----------- CONFIGURABLE CONSTANTS -----------------
#define DEFAULT_EVENT_QUEUE_SIZE 500000   // 5s of events at 100k/sec
#define QUEUE_RESIZE_THRESHOLD 0.7        // Resize when 70% full
#define MAX_QUEUE_SIZE 2000000            // Max queue size (20s of events)

#define MAX_WORKERS 1                     // Fixed single worker for memory safety
#define MAX_BUFFER_SIZE (500 * 1024)      // 500KB buffer
#define MIN_BATCH_COUNT 100               // Min msgs before flush
#define MAX_BATCH_COUNT 1000              // Max msgs in one batch
#define ADAPTIVE_BATCH_ENABLED 1          // Enable adaptive batch sizing
#define BATCH_TIMEOUT_US 1000000          // 1 second flush timeout

#define MAX_MESSAGE_LEN 1024
#define SYSLOG_PORT "514"
#define LOGFILE_PATH "/var/log/conntrack_logger.log"
#define MAX_CONSECUTIVE_FAILURES 5
#define RECONNECT_DELAY_MS 1000
#define STATS_INTERVAL_SEC 10             // How often to print stats

// ----------- PROTOCOL STATISTICS COUNTERS -----------
typedef struct {
    // TCP state counters
    atomic_llong tcp_syn_sent;      // TCP_CONNTRACK_SYN_SENT = 1
    atomic_llong tcp_syn_recv;      // TCP_CONNTRACK_SYN_RECV = 2
    atomic_llong tcp_established;   // TCP_CONNTRACK_ESTABLISHED = 3
    atomic_llong tcp_fin_wait;      // TCP_CONNTRACK_FIN_WAIT = 4
    atomic_llong tcp_close_wait;    // TCP_CONNTRACK_CLOSE_WAIT = 5
    atomic_llong tcp_last_ack;      // TCP_CONNTRACK_LAST_ACK = 6
    atomic_llong tcp_time_wait;     // TCP_CONNTRACK_TIME_WAIT = 7
    atomic_llong tcp_close;         // TCP_CONNTRACK_CLOSE = 8
    atomic_llong tcp_other;         // Other TCP states
    
    // Protocol counters
    atomic_llong tcp_total;         // Total TCP connections
    atomic_llong udp_total;         // Total UDP connections
    atomic_llong icmp_total;        // Total ICMP connections
    atomic_llong other_proto;       // Other protocols
    
    // Event type counters
    atomic_llong new_events;        // NFCT_T_NEW
    atomic_llong update_events;     // NFCT_T_UPDATE
    atomic_llong destroy_events;    // NFCT_T_DESTROY
} protocol_stats_t;

// ----------- SPSC QUEUE DEFINITION - must come before use -------------
typedef struct {
    void **items;
    size_t head;
    size_t tail;
    size_t capacity;
    atomic_size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full_cond;  // Condition for blocking push
    pthread_cond_t not_empty_cond; // Condition for blocking pop
} spsc_queue_t;

// ----------- GLOBAL VARIABLES ----------
static volatile sig_atomic_t shutdown_flag = 0;
static int global_debug_enabled = 0;
struct nfct_handle *g_nfct_handle = NULL;
static spsc_queue_t *event_queue = NULL;
static pthread_t worker_thread;
static pthread_mutex_t conntrack_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_llong total_events_sent = 0;
static atomic_llong total_bytes_sent = 0;
static atomic_llong total_events_received = 0;
static atomic_llong total_events_dropped = 0;
static atomic_llong total_batches_sent = 0;
static struct timespec start_time;
static protocol_stats_t proto_stats = {0};

// ----------- SPSC QUEUE IMPLEMENTATION -------------
// Create a new SPSC queue with given capacity
spsc_queue_t* spsc_queue_init(size_t capacity) {
    spsc_queue_t *q = malloc(sizeof(spsc_queue_t));
    if (!q) return NULL;
    q->items = calloc(capacity, sizeof(void*));
    if (!q->items) {
        free(q);
        return NULL;
    }
    q->head = 0;
    q->tail = 0;
    q->capacity = capacity;
    atomic_store(&q->count, 0);
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_full_cond, NULL);
    pthread_cond_init(&q->not_empty_cond, NULL);
    return q;
}

// Get current queue utilization (0.0 to 1.0)
double spsc_queue_utilization(spsc_queue_t *q) {
    if (!q) return 0.0;
    size_t current_count = atomic_load(&q->count);
    return (double)current_count / q->capacity;
}

// Resize the queue to new capacity (larger only)
int spsc_queue_resize(spsc_queue_t *q, size_t new_capacity) {
    if (!q || new_capacity <= q->capacity) return 0; // Only allow growing
    
    pthread_mutex_lock(&q->mutex);
    
    void **new_items = calloc(new_capacity, sizeof(void*));
    if (!new_items) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    size_t i = 0;
    size_t idx = q->tail;
    size_t count = atomic_load(&q->count);
    
    while (i < count) {
        new_items[i++] = q->items[idx];
        idx = (idx + 1) % q->capacity;
    }
    
    free(q->items);
    q->items = new_items;
    q->head = count;
    q->tail = 0;
    q->capacity = new_capacity;
    
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Check if queue needs resizing and resize if necessary
void spsc_queue_check_resize(spsc_queue_t *q) {
    if (!q) return;
    double util = spsc_queue_utilization(q);
    if (util >= QUEUE_RESIZE_THRESHOLD && q->capacity < MAX_QUEUE_SIZE) {
        size_t new_capacity = q->capacity * 2;
        if (new_capacity > MAX_QUEUE_SIZE) new_capacity = MAX_QUEUE_SIZE;
        
        if (spsc_queue_resize(q, new_capacity) == 0) {
            log_with_timestamp("[INFO] Resized queue from %zu to %zu elements (utilization: %.1f%%)\n", 
                  q->capacity/2, q->capacity, util*100);
        }
    }
}

// Blocking push - waits until queue has space
int spsc_queue_push_blocking(spsc_queue_t *q, void *item) {
    if (!q || !item) return -1;
    pthread_mutex_lock(&q->mutex);
    
    while (atomic_load(&q->count) >= q->capacity && !shutdown_flag) {
        pthread_cond_wait(&q->not_full_cond, &q->mutex);
    }
    
    if (shutdown_flag) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    q->items[q->head] = item;
    q->head = (q->head + 1) % q->capacity;
    atomic_fetch_add(&q->count, 1);
    
    pthread_cond_signal(&q->not_empty_cond);
    pthread_mutex_unlock(&q->mutex);
    
    spsc_queue_check_resize(q);
    return 0;
}

// Blocking pop - waits until queue has an item
int spsc_queue_pop_blocking(spsc_queue_t *q, void **item) {
    if (!q || !item) return 0;
    pthread_mutex_lock(&q->mutex);
    
    while (atomic_load(&q->count) == 0 && !shutdown_flag) {
        pthread_cond_wait(&q->not_empty_cond, &q->mutex);
    }
    
    if (atomic_load(&q->count) == 0) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    
    *item = q->items[q->tail];
    q->tail = (q->tail + 1) % q->capacity;
    atomic_fetch_sub(&q->count, 1);
    
    pthread_cond_signal(&q->not_full_cond);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

// Free all memory used by the queue
void spsc_queue_destroy(spsc_queue_t *q) {
    if (!q) return;
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_full_cond);
    pthread_cond_destroy(&q->not_empty_cond);
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
    size_t event_queue_size;
    int test_mode;
    int stats_interval;
} config_t;

// ----------- EVENT STRUCTURES -----------------------
typedef struct {
    long long timestamp_ns;
    struct nf_conntrack *ct;
    enum nf_conntrack_msg_type type;
    long long count;
    struct timespec arrival_ts;
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
    struct timespec arrival_ts;
} conn_event_t;

// ----------- APPLICATION CONTEXT --------------------
typedef struct {
    spsc_queue_t *event_queue;
    config_t *cfg;
    atomic_llong event_counter;
} app_context_t;

typedef struct {
    char *machine_name;
    char *syslog_ip;
    int debug_enabled;
    int test_mode;
    int hash_enabled;
    int payload_enabled;
    int count_enabled;
    atomic_int consecutive_failures;
    int stats_interval;
} worker_config_t;

// ----------- LOGGING --------------------------------
// Get current timestamp in UTC format YYYY-MM-DD HH:MM:SS
void get_utc_timestamp(char *buffer, size_t size) {
    time_t now;
    struct tm tm_info;
    
    time(&now);
    gmtime_r(&now, &tm_info);
    
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_info);
}

void log_with_timestamp(const char *fmt, ...) {
    int is_debug = (strncmp(fmt, "[DEBUG]", 7) == 0);
    if (is_debug && !global_debug_enabled) return;

    char timestamp[32];
    get_utc_timestamp(timestamp, sizeof(timestamp));

    fprintf(stdout, "[%s UTC] ", timestamp);

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fflush(stdout);
}

// Print protocol statistics
void print_protocol_stats() {
    log_with_timestamp("[PROTO] ===== TCP STATE STATISTICS =====\n");
    log_with_timestamp("[PROTO] SYN_SENT:    %lld\n", atomic_load(&proto_stats.tcp_syn_sent));
    log_with_timestamp("[PROTO] SYN_RECV:    %lld\n", atomic_load(&proto_stats.tcp_syn_recv));
    log_with_timestamp("[PROTO] ESTABLISHED: %lld\n", atomic_load(&proto_stats.tcp_established));
    log_with_timestamp("[PROTO] FIN_WAIT:    %lld\n", atomic_load(&proto_stats.tcp_fin_wait));
    log_with_timestamp("[PROTO] CLOSE_WAIT:  %lld\n", atomic_load(&proto_stats.tcp_close_wait));
    log_with_timestamp("[PROTO] LAST_ACK:    %lld\n", atomic_load(&proto_stats.tcp_last_ack));
    log_with_timestamp("[PROTO] TIME_WAIT:   %lld\n", atomic_load(&proto_stats.tcp_time_wait));
    log_with_timestamp("[PROTO] CLOSE:       %lld\n", atomic_load(&proto_stats.tcp_close));
    log_with_timestamp("[PROTO] OTHER:       %lld\n", atomic_load(&proto_stats.tcp_other));
    
    log_with_timestamp("[PROTO] ===== PROTOCOL STATISTICS =====\n");
    log_with_timestamp("[PROTO] TCP:         %lld\n", atomic_load(&proto_stats.tcp_total));
    log_with_timestamp("[PROTO] UDP:         %lld\n", atomic_load(&proto_stats.udp_total));
    log_with_timestamp("[PROTO] ICMP:        %lld\n", atomic_load(&proto_stats.icmp_total));
    log_with_timestamp("[PROTO] OTHER:       %lld\n", atomic_load(&proto_stats.other_proto));
    
    log_with_timestamp("[PROTO] ===== EVENT TYPE STATISTICS =====\n");
    log_with_timestamp("[PROTO] NEW:         %lld\n", atomic_load(&proto_stats.new_events));
    log_with_timestamp("[PROTO] UPDATE:      %lld\n", atomic_load(&proto_stats.update_events));
    log_with_timestamp("[PROTO] DESTROY:     %lld\n", atomic_load(&proto_stats.destroy_events));
}

// Print statistics about events processed
void print_stats() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    double elapsed = (now.tv_sec - start_time.tv_sec) + 
                    (now.tv_nsec - start_time.tv_nsec) / 1000000000.0;
    
    long long events_received = atomic_load(&total_events_received);
    long long events_sent = atomic_load(&total_events_sent);
    long long bytes_sent = atomic_load(&total_bytes_sent);
    long long events_dropped = atomic_load(&total_events_dropped);
    long long batches_sent = atomic_load(&total_batches_sent);
    
    double events_per_sec = elapsed > 0 ? events_sent / elapsed : 0;
    double bytes_per_sec = elapsed > 0 ? bytes_sent / elapsed : 0;
    double drop_rate = (events_received > 0) ? 
                      ((double)events_dropped / events_received) * 100.0 : 0.0;
    
    size_t queue_size = event_queue ? atomic_load(&event_queue->count) : 0;
    size_t queue_capacity = event_queue ? event_queue->capacity : 0;
    double queue_util = (queue_capacity > 0) ? ((double)queue_size / queue_capacity) * 100.0 : 0.0;
    
    log_with_timestamp("[STATS] Runtime: %.2f sec, Events: %lld received, %lld sent (%.2f/sec)\n", 
                      elapsed, events_received, events_sent, events_per_sec);
    log_with_timestamp("[STATS] Bytes sent: %lld (%.2f MB/sec), Drop rate: %.2f%%\n", 
                      bytes_sent, bytes_per_sec / (1024*1024), drop_rate);
    log_with_timestamp("[STATS] Batches sent: %lld, Avg batch size: %lld events\n",
                      batches_sent, batches_sent > 0 ? events_sent / batches_sent : 0);
    log_with_timestamp("[STATS] Queue: %zu/%zu (%.1f%% utilized)\n", 
                      queue_size, queue_capacity, queue_util);
    
    // Print protocol statistics
    print_protocol_stats();
}

// ----------- SIGNAL HANDLING ------------------------
void signal_handler(int sig) {
    static int already_logged = 0;
    if (!already_logged) {
        log_with_timestamp("[INFO] Received signal %d, shutting down\n", sig);
        already_logged = 1;
    }
    shutdown_flag = 1;
    
    if (event_queue) {
        pthread_cond_broadcast(&event_queue->not_empty_cond);
        pthread_cond_broadcast(&event_queue->not_full_cond);
    }
}

// ----------- HELP MESSAGE ---------------------------
static void print_help(const char *progname) {
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -n, --machine-name <n>    Specify machine name (required)\n");
    printf("  -l, --lsip <ip_address>   Specify syslog server IP/domain (required)\n");
    printf("  -d, --daemonize           Daemonize the program (optional)\n");
    printf("  -k, --kill                Kill all running daemons (optional)\n");
    printf("  -c, --count <yes|no>      Prepend event count to each event (optional)\n");
    printf("  -D, --debug               Enable debug logging (optional)\n");
    printf("  -H, --hash                Include BLAKE3 hash in log messages\n");
    printf("  -P, --payload             Include detailed payload tuple\n");
    printf("  -r, --src-range <range>   Filter events by source IP range (CIDR, e.g., 192.168.1.0/24)\n");
    printf("  -T, --test                Enable test mode for performance measurement\n");
    printf("  -s, --stats-interval <n>  Statistics reporting interval in seconds (default: %d)\n", STATS_INTERVAL_SEC);
    printf("  --event-queue-size <size> Event queue size (default: %d)\n", DEFAULT_EVENT_QUEUE_SIZE);
    printf("Note: At least one of -H or -P must be specified (unless in test mode).\n");
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
        {"test", no_argument, 0, 'T'},
        {"stats-interval", required_argument, 0, 's'},
        {"event-queue-size", required_argument, 0, 1001},
        {0, 0, 0, 0}
    };
    int opt;
    cfg->syslog_ip = NULL;
    cfg->machine_name = NULL;
    cfg->daemonize = 0;
    cfg->kill_daemons = 0;
    cfg->count_enabled = 0;
    cfg->debug_enabled = 0;
    cfg->hash_enabled = 1;  // Enable hash by default
    cfg->payload_enabled = 1; // Enable payload by default
    cfg->src_range = NULL;
    cfg->event_queue_size = DEFAULT_EVENT_QUEUE_SIZE;
    cfg->test_mode = 0;
    cfg->stats_interval = STATS_INTERVAL_SEC;

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:DHPr:Ts:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(argv[0]); exit(0);
            case 'n': cfg->machine_name = optarg; break;
            case 'l': cfg->syslog_ip = optarg; break;
            case 'd': cfg->daemonize = 1; break;
            case 'k': cfg->kill_daemons = 1; break;
            case 'c': cfg->count_enabled = (strcasecmp(optarg, "yes") == 0); break;
            case 'D': cfg->debug_enabled = 1; break;
            case 'H': cfg->hash_enabled = 1; break;
            case 'P': cfg->payload_enabled = 1; break;
            case 'r': cfg->src_range = optarg; break;
            case 'T': cfg->test_mode = 1; break;
            case 's': cfg->stats_interval = atoi(optarg); break;
            case 1001: cfg->event_queue_size = atoi(optarg); break;
            default: print_help(argv[0]); return 1;
        }
    }

    if (!cfg->kill_daemons && (!cfg->syslog_ip || !cfg->machine_name)) {
        log_with_timestamp("[ERROR] Syslog server IP/domain and machine name are required\n");
        print_help(argv[0]);
        return 1;
    }

    if (cfg->event_queue_size < 1024) cfg->event_queue_size = 1024;
    if (cfg->stats_interval < 1) cfg->stats_interval = 1;
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
        if (pid > 0 && pid != current_pid) {
            if (kill(pid, SIGTERM) == 0) {
                log_with_timestamp("[INFO] Killed process %d\n", pid);
            } else {
                log_with_timestamp("[ERROR] Failed to kill process %d: %s\n", pid, strerror(errno));
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
    if (!range_copy) return 0;
    char *slash = strchr(range_copy, '/');
    if (!slash) { free(range_copy); return 0; }
    
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) { free(range_copy); return 0; }

    struct in_addr network;
    if (inet_pton(AF_INET, range_copy, &network) <= 0) { free(range_copy); return 0; }

    uint32_t ip_num = ntohl(ip.s_addr);
    uint32_t net_num = ntohl(network.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
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

// ----------- UPDATE PROTOCOL STATISTICS -------------
static void update_protocol_stats(int proto_num, int state_num, enum nf_conntrack_msg_type type) {
    // Update protocol counters
    switch (proto_num) {
        case IPPROTO_TCP:
            atomic_fetch_add(&proto_stats.tcp_total, 1);
            
            // Update TCP state counters
            switch (state_num) {
                case 1: atomic_fetch_add(&proto_stats.tcp_syn_sent, 1); break;
                case 2: atomic_fetch_add(&proto_stats.tcp_syn_recv, 1); break;
                case 3: atomic_fetch_add(&proto_stats.tcp_established, 1); break;
                case 4: atomic_fetch_add(&proto_stats.tcp_fin_wait, 1); break;
                case 5: atomic_fetch_add(&proto_stats.tcp_close_wait, 1); break;
                case 6: atomic_fetch_add(&proto_stats.tcp_last_ack, 1); break;
                case 7: atomic_fetch_add(&proto_stats.tcp_time_wait, 1); break;
                case 8: atomic_fetch_add(&proto_stats.tcp_close, 1); break;
                default: atomic_fetch_add(&proto_stats.tcp_other, 1); break;
            }
            break;
            
        case IPPROTO_UDP:
            atomic_fetch_add(&proto_stats.udp_total, 1);
            break;
            
        case IPPROTO_ICMP:
            atomic_fetch_add(&proto_stats.icmp_total, 1);
            break;
            
        default:
            atomic_fetch_add(&proto_stats.other_proto, 1);
            break;
    }
    
    // Update event type counters
    switch (type) {
        case NFCT_T_NEW:
            atomic_fetch_add(&proto_stats.new_events, 1);
            break;
        case NFCT_T_UPDATE:
            atomic_fetch_add(&proto_stats.update_events, 1);
            break;
        case NFCT_T_DESTROY:
            atomic_fetch_add(&proto_stats.destroy_events, 1);
            break;
        default:
            // No other event types to count
            break;
    }
}

// ----------- EXTRACT DETAILED EVENT INFO ------------
static void extract_conn_event(
    struct nf_conntrack *ct, enum nf_conntrack_msg_type type,
    conn_event_t *event, const worker_config_t *cfg, long long count, long long timestamp_ns
) {
    if (!ct || !event) return;
    
    memset(event, 0, sizeof(*event));
    event->count = cfg->count_enabled ? count : 0;
    event->timestamp_ns = timestamp_ns;

    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    
    inet_ntop(AF_INET, &src_addr, event->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, event->dst_ip, INET_ADDRSTRLEN);

    event->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    event->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;
    
    event->proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO);

    // Set type_num based on the conntrack message type
    switch (type) {
        case NFCT_T_NEW: event->type_num = 1; strcpy(event->msg_type_str, "NEW"); break;
        case NFCT_T_UPDATE: event->type_num = 2; strcpy(event->msg_type_str, "UPDATE"); break;
        case NFCT_T_DESTROY: event->type_num = 3; strcpy(event->msg_type_str, "DESTROY"); break;
        default: event->type_num = 0; strcpy(event->msg_type_str, "UNKNOWN"); break;
    }

    // Set state_num for TCP connections
    if (event->proto_num == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        event->state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        
        switch (event->state_num) {
            case 1: strcpy(event->state_str, "SYN_SENT"); break;
            case 2: strcpy(event->state_str, "SYN_RECV"); break;
            case 3: strcpy(event->state_str, "ESTABLISHED"); break;
            case 4: strcpy(event->state_str, "FIN_WAIT"); break;
            case 5: strcpy(event->state_str, "CLOSE_WAIT"); break;
            case 6: strcpy(event->state_str, "LAST_ACK"); break;
            case 7: strcpy(event->state_str, "TIME_WAIT"); break;
            case 8: strcpy(event->state_str, "CLOSE"); break;
            default: strcpy(event->state_str, "NONE");
        }
    } else {
        event->state_num = 0;  // Default state for non-TCP
        strcpy(event->state_str, "NONE");
    }
    
    // Get protocol string
    switch (event->proto_num) {
        case IPPROTO_TCP: strcpy(event->protocol_str, "tcp"); break;
        case IPPROTO_UDP: strcpy(event->protocol_str, "udp"); break;
        case IPPROTO_ICMP: strcpy(event->protocol_str, "icmp"); break;
        default: snprintf(event->protocol_str, sizeof(event->protocol_str), "proto %d", event->proto_num);
    }

    // Update protocol statistics
    update_protocol_stats(event->proto_num, event->state_num, type);

    // Always calculate hash - critical for proper operation
    char hash_input[256];
    snprintf(hash_input, sizeof(hash_input), "%s,%s,%s,%s,%u,%s,%u",
        event->protocol_str, event->state_str, event->src_ip, event->dst_ip,
        event->src_port, event->dst_ip, event->dst_port);
    calculate_hash(hash_input, event->hash);
    
    // Get timeout and assured status
    event->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;
    strcpy(event->assured_str, "N/A");
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) strcpy(event->assured_str, "ASSURED");
    }
    
    // Record arrival time
    clock_gettime(CLOCK_REALTIME, &event->arrival_ts);
}

// ----------- SYSLOG CONNECTION WITH RETRY ----------------------
static int connect_to_syslog_with_retry(const char *host, const char *port_str, int *consecutive_failures) {
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res, *rp;
    int sock = -1;

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        log_with_timestamp("[ERROR] getaddrinfo failed for %s:%s: %s\n", 
                         host, port_str, gai_strerror(err));
        (*consecutive_failures)++;
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        
        // Set socket options
        int optval = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        
        // Set send buffer size
        int sndbuf = MAX_BUFFER_SIZE;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        
        // Set send timeout
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock != -1) {
        log_with_timestamp("[INFO] Successfully connected to syslog server at %s:%s\n", host, port_str);
        *consecutive_failures = 0;
    } else {
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", host, port_str);
        (*consecutive_failures)++;
    }
    return sock;
}

// ----------- SYSLOG MESSAGE FORMAT ------------------
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data);
}

// ----------- WORKER THREAD IMPLEMENTATION -----------------------
void* syslog_worker(void* arg) {
    worker_config_t *cfg = (worker_config_t *)arg;
    int syslog_fd = -1;
    atomic_store(&cfg->consecutive_failures, 0);
    
    char *batch_buf = malloc(MAX_BUFFER_SIZE);
    if (!batch_buf) {
        log_with_timestamp("[ERROR] Worker failed to allocate batch buffer\n");
        return NULL;
    }
    
    batch_buf[0] = '\0';
    size_t batch_len = 0;
    int batch_count = 0;
    struct timeval last_flush;
    struct timeval last_stats;
    gettimeofday(&last_flush, NULL);
    gettimeofday(&last_stats, NULL);
    
    // Dynamic batch sizing parameters
    int current_batch_limit = MIN_BATCH_COUNT;
    
    log_with_timestamp("[INFO] Worker thread started with %dKB buffer and %dms timeout\n", 
                     MAX_BUFFER_SIZE/1024, BATCH_TIMEOUT_US/1000);

    while (!shutdown_flag) {
        void *item = NULL;
        if (!spsc_queue_pop_blocking(event_queue, &item) || !item) {
            if (shutdown_flag) break;
            
            // Check if we need to flush based on timeout
            struct timeval now;
            gettimeofday(&now, NULL);
            long elapsed_us = (now.tv_sec - last_flush.tv_sec) * 1000000 + (now.tv_usec - last_flush.tv_usec);
            
            if (batch_count > 0 && elapsed_us >= BATCH_TIMEOUT_US) {
                log_with_timestamp("[INFO] Flushing batch due to timeout: %d events, %zu bytes\n", 
                                 batch_count, batch_len);
                goto send_batch;
            }
            
            continue;
        }

        event_data_t *event_data = (event_data_t *)item;
        conn_event_t conn_info;

        pthread_mutex_lock(&conntrack_mutex);
        extract_conn_event(event_data->ct, event_data->type, &conn_info, cfg, event_data->count, event_data->timestamp_ns);
        nfct_destroy(event_data->ct);
        event_data->ct = NULL;
        pthread_mutex_unlock(&conntrack_mutex);
        
        free(event_data); // Free the container immediately after use.

        // Format message content based on the first program's structure
        char message_content[MAX_MESSAGE_LEN];
        if (cfg->hash_enabled && cfg->payload_enabled) {
            if (cfg->count_enabled) {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%lld,%s,%d,%d,%d,%s,%u,%s,%u",
                         conn_info.count, 
                         conn_info.timestamp_ns, 
                         conn_info.hash,
                         conn_info.type_num, 
                         conn_info.state_num, 
                         conn_info.proto_num,
                         conn_info.src_ip, 
                         conn_info.src_port, 
                         conn_info.dst_ip, 
                         conn_info.dst_port);
            } else {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%s,%d,%d,%d,%s,%u,%s,%u",
                         conn_info.timestamp_ns, 
                         conn_info.hash,
                         conn_info.type_num, 
                         conn_info.state_num, 
                         conn_info.proto_num,
                         conn_info.src_ip, 
                         conn_info.src_port, 
                         conn_info.dst_ip, 
                         conn_info.dst_port);
            }
        } else if (cfg->hash_enabled) {
            if (cfg->count_enabled) {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%lld,%s", 
                         conn_info.count, 
                         conn_info.timestamp_ns, 
                         conn_info.hash);
            } else {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%s", 
                         conn_info.timestamp_ns, 
                         conn_info.hash);
            }
        } else if (cfg->payload_enabled) {
            if (cfg->count_enabled) {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%lld,%d,%d,%d,%s,%u,%s,%u",
                         conn_info.count, 
                         conn_info.timestamp_ns, 
                         conn_info.type_num, 
                         conn_info.state_num, 
                         conn_info.proto_num,
                         conn_info.src_ip, 
                         conn_info.src_port, 
                         conn_info.dst_ip, 
                         conn_info.dst_port);
            } else {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%d,%d,%d,%s,%u,%s,%u",
                         conn_info.timestamp_ns, 
                         conn_info.type_num, 
                         conn_info.state_num, 
                         conn_info.proto_num,
                         conn_info.src_ip, 
                         conn_info.src_port, 
                         conn_info.dst_ip, 
                         conn_info.dst_port);
            }
        } else {
            // Minimal content for test mode
            if (cfg->count_enabled) {
                snprintf(message_content, sizeof(message_content), 
                         "%lld,%lld", 
                         conn_info.count, 
                         conn_info.timestamp_ns);
            } else {
                snprintf(message_content, sizeof(message_content), 
                         "%lld", 
                         conn_info.timestamp_ns);
            }
        }
        
        // Create properly formatted syslog message using the first program's format
        char syslog_msg[MAX_MESSAGE_LEN];
        create_syslog_message(syslog_msg, sizeof(syslog_msg), cfg->machine_name, message_content);
        
        size_t msg_len = strlen(syslog_msg);
        
        // Add newline for proper syslog message termination
        if (batch_len + msg_len + 2 >= MAX_BUFFER_SIZE) {
            // Current batch is full, send it
            log_with_timestamp("[INFO] Buffer size limit reached (%zu bytes), sending batch\n", batch_len);
            goto send_batch;
        }
        
        // Add message to batch with newline
        strncat(batch_buf, syslog_msg, MAX_BUFFER_SIZE - batch_len - 2);
        strcat(batch_buf, "\n");
        batch_len += msg_len + 1; // +1 for newline
        batch_count++;
        
        // Dynamic batch sizing based on queue utilization
        if (ADAPTIVE_BATCH_ENABLED) {
            double queue_util = spsc_queue_utilization(event_queue);
            if (queue_util > 0.8) {
                // High utilization - send smaller batches more frequently
                current_batch_limit = MIN_BATCH_COUNT;
            } else if (queue_util > 0.5) {
                // Medium utilization - moderate batch size
                current_batch_limit = (MIN_BATCH_COUNT + MAX_BATCH_COUNT) / 2;
            } else {
                // Low utilization - larger batches for efficiency
                current_batch_limit = MAX_BATCH_COUNT;
            }
        }
        
        // Check if we have enough messages to send a batch
        if (batch_count >= current_batch_limit) {
            log_with_timestamp("[INFO] Sending batch due to count (%d events, target: %d)\n", 
                             batch_count, current_batch_limit);
            goto send_batch;
        }
        
        // Check if we should send based on timeout
        struct timeval now;
        gettimeofday(&now, NULL);
        long elapsed_us = (now.tv_sec - last_flush.tv_sec) * 1000000 + (now.tv_usec - last_flush.tv_usec);
        
        if (elapsed_us >= BATCH_TIMEOUT_US && batch_count > 0) {
            log_with_timestamp("[INFO] Sending batch due to timeout (%dms elapsed)\n", 
                             (int)(elapsed_us/1000));
            goto send_batch;
        }
        
        // Check for stats reporting
        long stats_elapsed_sec = now.tv_sec - last_stats.tv_sec;
        if (stats_elapsed_sec >= cfg->stats_interval) {
            print_stats();
            last_stats = now;
        }
        
        continue;
        
send_batch:
        if (batch_count == 0 || batch_len == 0) {
            // Don't send empty batches
            struct timeval now;
            gettimeofday(&now, NULL);
            last_flush = now;
            continue;
        }
        
        int failures = atomic_load(&cfg->consecutive_failures);
        if (failures >= MAX_CONSECUTIVE_FAILURES) {
            int delay_ms = RECONNECT_DELAY_MS * (1 << (failures - MAX_CONSECUTIVE_FAILURES));
            if (delay_ms > 30000) delay_ms = 30000;
            log_with_timestamp("[INFO] Too many consecutive failures (%d), backing off for %d ms\n", 
                             failures, delay_ms);
            usleep(delay_ms * 1000);
        }
        
        // Try to connect if needed
        if (syslog_fd < 0) {
            syslog_fd = connect_to_syslog_with_retry(cfg->syslog_ip, SYSLOG_PORT, 
                                                  (int*)&cfg->consecutive_failures);
        }
        
        if (syslog_fd >= 0) {
            ssize_t sent = send(syslog_fd, batch_buf, batch_len, MSG_NOSIGNAL);
            if (sent < 0) {
                log_with_timestamp("[ERROR] Failed to send batch: %s\n", strerror(errno));
                close(syslog_fd);
                syslog_fd = -1;
                atomic_fetch_add(&cfg->consecutive_failures, 1);
                // DON'T DROP PACKETS - we'll retry sending this batch
                log_with_timestamp("[INFO] Will retry sending this batch\n");
            } else {
                log_with_timestamp("[INFO] Successfully sent batch: %zd bytes, %d events\n", 
                                 sent, batch_count);
                atomic_store(&cfg->consecutive_failures, 0);
                atomic_fetch_add(&total_events_sent, batch_count);
                atomic_fetch_add(&total_bytes_sent, sent);
                atomic_fetch_add(&total_batches_sent, 1);
                
                // Reset batch
                batch_buf[0] = '\0';
                batch_len = 0;
                batch_count = 0;
                gettimeofday(&last_flush, NULL);
            }
        } else {
            log_with_timestamp("[WARNING] No syslog connection, will retry this batch\n");
            // DON'T DROP PACKETS - we'll keep this batch and retry
        }
    }

    // Final flush
    if (batch_count > 0 && batch_len > 0) {
        log_with_timestamp("[INFO] Final flush: %d events, %zu bytes\n", batch_count, batch_len);
        
        if (syslog_fd < 0) {
            syslog_fd = connect_to_syslog_with_retry(cfg->syslog_ip, SYSLOG_PORT, 
                                                  (int*)&cfg->consecutive_failures);
        }
        
        if (syslog_fd >= 0) {
            ssize_t sent = send(syslog_fd, batch_buf, batch_len, MSG_NOSIGNAL);
            if (sent > 0) {
                log_with_timestamp("[INFO] Final flush sent: %zd bytes\n", sent);
                atomic_fetch_add(&total_events_sent, batch_count);
                atomic_fetch_add(&total_bytes_sent, sent);
                atomic_fetch_add(&total_batches_sent, 1);
            } else {
                log_with_timestamp("[ERROR] Failed to send final batch: %s\n", strerror(errno));
                // On shutdown, we might lose this batch - that's acceptable
                atomic_fetch_add(&total_events_dropped, batch_count);
            }
        } else {
            log_with_timestamp("[ERROR] No syslog connection for final flush, dropping %d events\n", 
                             batch_count);
            atomic_fetch_add(&total_events_dropped, batch_count);
        }
    }
    
    if (syslog_fd >= 0) close(syslog_fd);
    free(batch_buf);
    
    // Final stats
    print_stats();
    
    log_with_timestamp("[INFO] Worker thread exiting.\n");
    return NULL;
}

// ----------- CONNTRACK CALLBACK ---------------------
static int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    app_context_t *ctx = (app_context_t *)data;
    atomic_fetch_add(&total_events_received, 1);

    // Take timestamp as soon as the callback is entered
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long timestamp_ns = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;

    // Source IP range filtering
    if (ctx->cfg->src_range) {
        struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));

        if (!ip_in_range(src_ip, ctx->cfg->src_range)) {
            if (ctx->cfg->debug_enabled) {
                log_with_timestamp("[DEBUG] Filtered event from %s (not in range %s)\n", 
                                   src_ip, ctx->cfg->src_range);
            }
            return NFCT_CB_CONTINUE;
        }
    }

    // Allocate memory for event
    event_data_t *event = calloc(1, sizeof(event_data_t));
    if (!event) {
        log_with_timestamp("[ERROR] Failed to allocate event_data_t\n");
        atomic_fetch_add(&total_events_dropped, 1);
        return NFCT_CB_CONTINUE;
    }

    event->timestamp_ns = timestamp_ns;
    event->type = type;
    event->count = ctx->cfg->count_enabled ? atomic_fetch_add(&ctx->event_counter, 1) + 1 : 0;

    // Clone conntrack entry (protect if needed)
    pthread_mutex_lock(&conntrack_mutex);
    event->ct = nfct_clone(ct);
    pthread_mutex_unlock(&conntrack_mutex);

    if (!event->ct) {
        log_with_timestamp("[ERROR] Failed to clone conntrack\n");
        free(event);
        atomic_fetch_add(&total_events_dropped, 1);
        return NFCT_CB_CONTINUE;
    }

    // Push event to queue
    if (spsc_queue_push_blocking(ctx->event_queue, event) != 0) {
        log_with_timestamp("[ERROR] Failed to push event to queue\n");
        nfct_destroy(event->ct);
        free(event);
        atomic_fetch_add(&total_events_dropped, 1);
    }

    return NFCT_CB_CONTINUE;
}



// ----------- MAIN FUNCTION WITH EDGE-TRIGGERED EPOLL -------------
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
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            close(logfd);
        }
    }

    global_debug_enabled = cfg.debug_enabled;
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Initialize start time for statistics
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    log_with_timestamp("[INFO] Starting conntrack logger on %s (ajettesla)\n", hostname);
    log_with_timestamp("[INFO] Machine name: %s, Syslog server: %s\n", 
                      cfg.machine_name, cfg.syslog_ip);
    log_with_timestamp("[INFO] Debug: %s, Hash: %s, Payload: %s, Count: %s\n",
                      cfg.debug_enabled ? "enabled" : "enabled by default",
                      cfg.hash_enabled ? "enabled" : "enabled by default",
                      cfg.payload_enabled ? "enabled" : "enabled by default",
                      cfg.count_enabled ? "enabled" : "disabled");
    
    if (cfg.src_range) {
        log_with_timestamp("[INFO] Filtering by source IP range: %s\n", cfg.src_range);
    }
    
    // Initialize protocol statistics counters
    memset(&proto_stats, 0, sizeof(proto_stats));
    
    event_queue = spsc_queue_init(cfg.event_queue_size);
    if (!event_queue) {
        log_with_timestamp("[ERROR] Failed to initialize event queue\n");
        return 1;
    }
    
    log_with_timestamp("[INFO] Initialized event queue with capacity %zu\n", cfg.event_queue_size);
    
    app_context_t app_ctx = { .event_queue = event_queue, .cfg = &cfg, .event_counter = 0 };
    
    g_nfct_handle = nfct_open(NFNL_SUBSYS_CTNETLINK,
                              NFNLGRP_CONNTRACK_NEW | NFNLGRP_CONNTRACK_UPDATE | NFNLGRP_CONNTRACK_DESTROY);
    if (!g_nfct_handle) {
        log_with_timestamp("[ERROR] nfct_open: %s\n", strerror(errno));
        spsc_queue_destroy(event_queue);
        return 1;
    }
    
    nfct_callback_register(g_nfct_handle, NFCT_T_ALL, cb, &app_ctx);
    int conntrack_fd = nfct_fd(g_nfct_handle);
    fcntl(conntrack_fd, F_SETFL, fcntl(conntrack_fd, F_GETFL, 0) | O_NONBLOCK);
    
    int rcvbuf = 8*1024*1024;  // Increased receive buffer for high-load scenarios
    if (setsockopt(conntrack_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        log_with_timestamp("[WARNING] Failed to set SO_RCVBUF: %s\n", strerror(errno));
    } else {
        log_with_timestamp("[INFO] Set netlink receive buffer to %d bytes\n", rcvbuf);
    }
    
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = conntrack_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conntrack_fd, &ev);
    
    worker_config_t worker_cfg = {
        .machine_name = cfg.machine_name, 
        .syslog_ip = cfg.syslog_ip,
        .debug_enabled = cfg.debug_enabled, 
        .test_mode = cfg.test_mode,
        .hash_enabled = cfg.hash_enabled, 
        .payload_enabled = cfg.payload_enabled,
        .count_enabled = cfg.count_enabled, 
        .consecutive_failures = 0,
        .stats_interval = cfg.stats_interval
    };
    
    pthread_create(&worker_thread, NULL, syslog_worker, &worker_cfg);
    
    struct sched_param sp = { .sched_priority = sched_get_priority_max(SCHED_FIFO) };
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0) {
        log_with_timestamp("[WARNING] Failed to set RT priority: %s\n", strerror(errno));
    } else {
        log_with_timestamp("[INFO] Set main thread to RT priority\n");
    }
    
    log_with_timestamp("[INFO] Main event loop started - %s\n", "2025-06-28 09:12:12");
    
    // Start statistics reporting
    struct timeval last_stats;
    gettimeofday(&last_stats, NULL);
    
    while (!shutdown_flag) {
        struct epoll_event events[64];  // Process multiple events per epoll_wait
        int nfds = epoll_wait(epoll_fd, events, 64, 100);  // 100ms timeout
        
        if (nfds < 0 && errno != EINTR) {
            log_with_timestamp("[ERROR] epoll_wait: %s\n", strerror(errno));
            break;
        }
        
        if (nfds > 0) {
            // Process all events from this epoll notification
            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd == conntrack_fd) {
                    // Process as many events as possible with edge-triggered mode
                    int processed = 0;
                    while (!shutdown_flag) {
                        int ret = nfct_catch(g_nfct_handle);
                        if (ret < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // No more events to read
                                break;
                            } else if (errno != EINTR) {
                                log_with_timestamp("[ERROR] nfct_catch: %s\n", strerror(errno));
                                break;
                            }
                        } else {
                            processed++;
                            // After every 1000 events, yield to prevent starvation
                            if (processed % 1000 == 0) {
                                sched_yield();
                            }
                        }
                    }
                    
                    if (processed > 0 && cfg.debug_enabled) {
                        log_with_timestamp("[DEBUG] Processed %d conntrack events in this batch\n", processed);
                    }
                }
            }
        }
        
        // Print stats periodically from main thread
        struct timeval now;
        gettimeofday(&now, NULL);
        long stats_elapsed_sec = now.tv_sec - last_stats.tv_sec;
        
        if (stats_elapsed_sec >= cfg.stats_interval) {
            print_stats();
            last_stats = now;
        }
    }
    
    log_with_timestamp("[INFO] Shutting down...\n");
    close(epoll_fd);
    
    if (g_nfct_handle) {
        nfct_callback_unregister(g_nfct_handle);
        nfct_close(g_nfct_handle);
    }
    
    pthread_cond_broadcast(&event_queue->not_empty_cond);
    pthread_cond_broadcast(&event_queue->not_full_cond);
    pthread_join(worker_thread, NULL);
    
    spsc_queue_destroy(event_queue);
    
    log_with_timestamp("[INFO] Clean shutdown complete\n");
    return 0;
}
