/*
 * Improved conntrack logger with optimized performance parameters
 * 
 * Key improvements:
 * - Efficient epoll implementation for event capture
 * - 500KB buffer size and 1-second timeout for syslog
 * - Dynamic SPSC queue resizing when 70% capacity is reached
 * - Connection monitoring thread for reliable syslog delivery
 * - Balanced thread scheduling to prevent event loss
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

// ----------- CONFIGURABLE CONSTANTS -----------------
#define DEFAULT_EVENT_QUEUE_SIZE 200000
#define DEFAULT_SYSLOG_QUEUE_SIZE 200000
#define MIN_BATCH_SIZE 100
#define MAX_BATCH_SIZE 1000
#define ADAPTIVE_BATCH_SIZE 1
#define MAX_MESSAGE_LEN 1024
#define BATCH_TIMEOUT_US 1000000  // 1 second (reduced from 20s)
#define SYSLOG_PORT "514"
#define LOGFILE_PATH "/var/log/conntrack_logger.log"
#define MAX_CONSECUTIVE_FAILURES 5
#define RECONNECT_DELAY_MS 1000
#define MAX_BUFFER_SIZE 512000    // 500KB (reduced from 5MB)
#define QUEUE_RESIZE_THRESHOLD 0.7 // Resize when 70% full
#define MAX_QUEUE_SIZE 1000000    // Maximum queue size after resizing

// ----------- TEST MODE STATISTICS -------------------
typedef struct {
    atomic_llong total_events;
    atomic_llong min_arrival_to_format_ns;
    atomic_llong max_arrival_to_format_ns;
    atomic_llong sum_arrival_to_format_ns;
    atomic_llong min_arrival_to_syslog_ns;
    atomic_llong max_arrival_to_syslog_ns;
    atomic_llong sum_arrival_to_syslog_ns;
    atomic_llong total_processed_events;
    atomic_llong total_sent_events;
    struct timespec start_time;
} test_stats_t;

// ----------- SPSC QUEUE IMPLEMENTATION -------------
typedef struct {
    void **items;
    size_t head;
    size_t tail;
    size_t capacity;
    atomic_size_t count;
    pthread_mutex_t resize_mutex; // Mutex for resizing operations
} spsc_queue_t;

// Create a new SPSC queue with given capacity
spsc_queue_t* spsc_queue_init(size_t capacity) {
    spsc_queue_t *q = malloc(sizeof(spsc_queue_t));
    if (!q) return NULL;
    q->items = malloc(sizeof(void*) * capacity);
    if (!q->items) {
        free(q);
        return NULL;
    }
    q->head = 0;
    q->tail = 0;
    q->capacity = capacity;
    atomic_store(&q->count, 0);
    pthread_mutex_init(&q->resize_mutex, NULL);
    return q;
}

// Get current queue utilization (0.0 to 1.0)
double spsc_queue_utilization(spsc_queue_t *q) {
    size_t current_count = atomic_load(&q->count);
    return (double)current_count / q->capacity;
}

// Resize the queue to new capacity (larger only)
int spsc_queue_resize(spsc_queue_t *q, size_t new_capacity) {
    if (new_capacity <= q->capacity) return 0; // Only allow growing
    
    pthread_mutex_lock(&q->resize_mutex);
    
    // Allocate new items array
    void **new_items = malloc(sizeof(void*) * new_capacity);
    if (!new_items) {
        pthread_mutex_unlock(&q->resize_mutex);
        return -1;
    }
    
    // Copy items to new array in order
    size_t i = 0;
    size_t idx = q->tail;
    size_t count = atomic_load(&q->count);
    
    while (i < count) {
        new_items[i++] = q->items[idx];
        idx = (idx + 1) % q->capacity;
    }
    
    // Update queue
    free(q->items);
    q->items = new_items;
    q->head = count;
    q->tail = 0;
    q->capacity = new_capacity;
    
    pthread_mutex_unlock(&q->resize_mutex);
    return 0;
}

// Check if queue needs resizing and resize if necessary
void spsc_queue_check_resize(spsc_queue_t *q) {
    double util = spsc_queue_utilization(q);
    if (util >= QUEUE_RESIZE_THRESHOLD && q->capacity < MAX_QUEUE_SIZE) {
        size_t new_capacity = q->capacity * 2;
        if (new_capacity > MAX_QUEUE_SIZE) new_capacity = MAX_QUEUE_SIZE;
        
        if (spsc_queue_resize(q, new_capacity) == 0) {
            printf("[INFO] Resized queue from %zu to %zu elements (utilization: %.1f%%)\n", 
                  q->capacity/2, q->capacity, util*100);
        }
    }
}

// Enqueue an item (returns 0 on success, -1 if queue full)
int spsc_queue_push(spsc_queue_t *q, void *item) {
    pthread_mutex_lock(&q->resize_mutex);
    size_t next_head = (q->head + 1) % q->capacity;
    if (next_head == q->tail) {
        pthread_mutex_unlock(&q->resize_mutex);
        return -1; // Queue full
    }
    q->items[q->head] = item;
    q->head = next_head;
    atomic_fetch_add(&q->count, 1);
    pthread_mutex_unlock(&q->resize_mutex);
    
    // Check if we need to resize (outside the critical section)
    spsc_queue_check_resize(q);
    return 0;
}

// Dequeue an item (returns 1 on success, 0 if empty)
int spsc_queue_try_pop(spsc_queue_t *q, void **item) {
    pthread_mutex_lock(&q->resize_mutex);
    if (q->tail == q->head) {
        pthread_mutex_unlock(&q->resize_mutex);
        return 0; // Queue empty
    }
    *item = q->items[q->tail];
    q->tail = (q->tail + 1) % q->capacity;
    atomic_fetch_sub(&q->count, 1);
    pthread_mutex_unlock(&q->resize_mutex);
    return 1;
}

// Free all memory used by the queue
void spsc_queue_destroy(spsc_queue_t *q) {
    pthread_mutex_destroy(&q->resize_mutex);
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
    size_t syslog_queue_size;
    int test_mode;  // New test mode flag
} config_t;

// ----------- EVENT STRUCTURES -----------------------
typedef struct {
    long long timestamp_ns;
    struct nf_conntrack *ct;
    enum nf_conntrack_msg_type type;
    long long count;
    struct timespec arrival_ts;  // Exact arrival time for test mode
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
    struct timespec arrival_ts;  // Pass through for test mode
} conn_event_t;

// ----------- APPLICATION CONTEXT --------------------
typedef struct {
    spsc_queue_t *event_queue;
    spsc_queue_t *syslog_queue;
    config_t *cfg;
    test_stats_t *test_stats;  // Test statistics
} app_context_t;

typedef struct {
    spsc_queue_t *queue;
    int debug_enabled;
    char *machine_name;
    char *syslog_ip;
    int syslog_fd;
    atomic_size_t bytes_transferred;
    atomic_int consecutive_failures;
    struct timespec last_failure_time;
    test_stats_t *test_stats;  // Reference to test statistics
    int test_mode;
} syslog_data_t;

// ----------- GLOBALS --------------------------------
static int global_debug_enabled = 0;
static atomic_llong event_counter = 0;
volatile sig_atomic_t shutdown_flag = 0;
struct nfct_handle *g_nfct_handle = NULL;
static atomic_int event_overflow_reported = 0;
static atomic_int syslog_overflow_reported = 0;
static test_stats_t global_test_stats = {0};

// ----------- TEST STATISTICS FUNCTIONS --------------
void init_test_stats(test_stats_t *stats) {
    atomic_store(&stats->total_events, 0);
    atomic_store(&stats->min_arrival_to_format_ns, LLONG_MAX);
    atomic_store(&stats->max_arrival_to_format_ns, 0);
    atomic_store(&stats->sum_arrival_to_format_ns, 0);
    atomic_store(&stats->min_arrival_to_syslog_ns, LLONG_MAX);
    atomic_store(&stats->max_arrival_to_syslog_ns, 0);
    atomic_store(&stats->sum_arrival_to_syslog_ns, 0);
    atomic_store(&stats->total_processed_events, 0);
    atomic_store(&stats->total_sent_events, 0);
    clock_gettime(CLOCK_REALTIME, &stats->start_time);
}

void update_format_timing(test_stats_t *stats, long long diff_ns) {
    atomic_fetch_add(&stats->total_processed_events, 1);
    atomic_fetch_add(&stats->sum_arrival_to_format_ns, diff_ns);
    
    // Update min
    long long current_min = atomic_load(&stats->min_arrival_to_format_ns);
    while (diff_ns < current_min) {
        if (atomic_compare_exchange_weak(&stats->min_arrival_to_format_ns, &current_min, diff_ns)) {
            break;
        }
    }
    
    // Update max
    long long current_max = atomic_load(&stats->max_arrival_to_format_ns);
    while (diff_ns > current_max) {
        if (atomic_compare_exchange_weak(&stats->max_arrival_to_format_ns, &current_max, diff_ns)) {
            break;
        }
    }
}

void update_syslog_timing(test_stats_t *stats, long long diff_ns) {
    atomic_fetch_add(&stats->total_sent_events, 1);
    atomic_fetch_add(&stats->sum_arrival_to_syslog_ns, diff_ns);
    
    // Update min
    long long current_min = atomic_load(&stats->min_arrival_to_syslog_ns);
    while (diff_ns < current_min) {
        if (atomic_compare_exchange_weak(&stats->min_arrival_to_syslog_ns, &current_min, diff_ns)) {
            break;
        }
    }
    
    // Update max
    long long current_max = atomic_load(&stats->max_arrival_to_syslog_ns);
    while (diff_ns > current_max) {
        if (atomic_compare_exchange_weak(&stats->max_arrival_to_syslog_ns, &current_max, diff_ns)) {
            break;
        }
    }
}

void print_test_stats(test_stats_t *stats) {
    struct timespec end_time;
    clock_gettime(CLOCK_REALTIME, &end_time);
    
    long long total_runtime_ns = (long long)(end_time.tv_sec - stats->start_time.tv_sec) * 1000000000LL +
                                (end_time.tv_nsec - stats->start_time.tv_nsec);
    
    long long total_events = atomic_load(&stats->total_events);
    long long processed_events = atomic_load(&stats->total_processed_events);
    long long sent_events = atomic_load(&stats->total_sent_events);
    
    printf("\n=== TEST MODE STATISTICS ===\n");
    printf("Runtime: %.3f seconds\n", total_runtime_ns / 1000000000.0);
    printf("Total events received: %lld\n", total_events);
    printf("Total events processed: %lld\n", processed_events);
    printf("Total events sent: %lld\n", sent_events);
    
    if (total_runtime_ns > 0) {
        printf("Event rate: %.2f events/second\n", (double)total_events * 1000000000.0 / total_runtime_ns);
    }
    
    if (processed_events > 0) {
        long long sum_format = atomic_load(&stats->sum_arrival_to_format_ns);
        long long min_format = atomic_load(&stats->min_arrival_to_format_ns);
        long long max_format = atomic_load(&stats->max_arrival_to_format_ns);
        
        printf("\nArrival to Formatting Times:\n");
        printf("  Min: %lld ns (%.3f µs)\n", min_format, min_format / 1000.0);
        printf("  Max: %lld ns (%.3f µs)\n", max_format, max_format / 1000.0);
        printf("  Avg: %lld ns (%.3f µs)\n", sum_format / processed_events, 
               (sum_format / processed_events) / 1000.0);
    }
    
    if (sent_events > 0) {
        long long sum_syslog = atomic_load(&stats->sum_arrival_to_syslog_ns);
        long long min_syslog = atomic_load(&stats->min_arrival_to_syslog_ns);
        long long max_syslog = atomic_load(&stats->max_arrival_to_syslog_ns);
        
        printf("\nArrival to Syslog Times:\n");
        printf("  Min: %lld ns (%.3f µs)\n", min_syslog, min_syslog / 1000.0);
        printf("  Max: %lld ns (%.3f µs)\n", max_syslog, max_syslog / 1000.0);
        printf("  Avg: %lld ns (%.3f µs)\n", sum_syslog / sent_events,
               (sum_syslog / sent_events) / 1000.0);
    }
    printf("============================\n\n");
}

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
void signal_handler(int sig) {
    static int already_logged = 0;
    if (!already_logged) {
        log_with_timestamp("[INFO] Received signal %d, shutting down\n", sig);
        already_logged = 1;
    }
    shutdown_flag = 1;
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
    printf("  --event-queue-size <size> Event queue size (default: %d)\n", DEFAULT_EVENT_QUEUE_SIZE);
    printf("  --syslog-queue-size <size> Syslog queue size (default: %d)\n", DEFAULT_SYSLOG_QUEUE_SIZE);
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
        {"event-queue-size", required_argument, 0, 1001},
        {"syslog-queue-size", required_argument, 0, 1002},
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
    cfg->event_queue_size = DEFAULT_EVENT_QUEUE_SIZE;
    cfg->syslog_queue_size = DEFAULT_SYSLOG_QUEUE_SIZE;
    cfg->test_mode = 0;

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:DHPr:T", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                exit(0);
            case 'n':
                cfg->machine_name = optarg;
                break;
            case 'l':
                cfg->syslog_ip = optarg;
                break;
            case 'd':
                cfg->daemonize = 1;
                break;
            case 'k':
                cfg->kill_daemons = 1;
                break;
            case 'c':
                if (strcasecmp(optarg, "yes") == 0) cfg->count_enabled = 1;
                else cfg->count_enabled = 0;
                break;
            case 'D':
                cfg->debug_enabled = 1;
                break;
            case 'H':
                cfg->hash_enabled = 1;
                break;
            case 'P':
                cfg->payload_enabled = 1;
                break;
            case 'r':
                cfg->src_range = optarg;
                break;
            case 'T':
                cfg->test_mode = 1;
                break;
            case 1001:
                cfg->event_queue_size = atoi(optarg);
                break;
            case 1002:
                cfg->syslog_queue_size = atoi(optarg);
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if (!cfg->kill_daemons && (!cfg->syslog_ip || !cfg->machine_name)) {
        log_with_timestamp("Syslog server IP/domain and machine name are required\n");
        print_help(argv[0]);
        return 1;
    }

    // In test mode, we don't require -H or -P
    if (!cfg->kill_daemons && !cfg->test_mode && !cfg->hash_enabled && !cfg->payload_enabled) {
        log_with_timestamp("Error: At least one of -H or -P must be specified (unless in test mode).\n");
        print_help(argv[0]);
        return 1;
    }

    // Validate queue sizes
    if (cfg->event_queue_size < 1024) cfg->event_queue_size = 1024;
    if (cfg->syslog_queue_size < 1024) cfg->syslog_queue_size = 1024;

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
    int payload_enabled, long long count, long long timestamp_ns,
    struct timespec *arrival_ts
) {
    event->count = count_enabled ? count : 0;
    event->timestamp_ns = timestamp_ns;
    
    // Copy arrival timestamp for test mode
    if (arrival_ts) {
        event->arrival_ts = *arrival_ts;
    } else {
        event->arrival_ts.tv_sec = 0;
        event->arrival_ts.tv_nsec = 0;
    }

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
            case NFCT_T_NEW:
                strcpy(event->msg_type_str, "NEW");
                break;
            case NFCT_T_UPDATE:
                strcpy(event->msg_type_str, "UPDATE");
                break;
            case NFCT_T_DESTROY:
                strcpy(event->msg_type_str, "DESTROY");
                break;
            default:
                strcpy(event->msg_type_str, "UNKNOWN");
                break;
        }

        if (event->state_num < 0 && event->proto_num == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
            event->state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        }
        if (event->state_num >= 0) {
            switch (event->state_num) {
                case 0:  strcpy(event->state_str, "NONE");       break;
                case 1:  strcpy(event->state_str, "SYN_SENT");   break;
                case 2:  strcpy(event->state_str, "SYN_RECV");   break;
                case 3:  strcpy(event->state_str, "ESTABLISHED");break;
                case 4:  strcpy(event->state_str, "FIN_WAIT");   break;
                case 5:  strcpy(event->state_str, "CLOSE_WAIT"); break;
                case 6:  strcpy(event->state_str, "LAST_ACK");   break;
                case 7:  strcpy(event->state_str, "TIME_WAIT");  break;
                case 8:  strcpy(event->state_str, "CLOSE");      break;
                default: strcpy(event->state_str, "UNKNOWN");    break;
            }
        } else {
            strcpy(event->state_str, "N/A");
        }
    }

    if (hash_enabled) {
        char hash_input[256];
        snprintf(
            hash_input, sizeof(hash_input), "%s,%s,%s,%s,%u,%u,%s",
            event->protocol_str, event->state_str, event->src_ip, event->dst_ip,
            event->src_port, event->dst_port, event->msg_type_str
        );
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
static int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    app_context_t *ctx = (app_context_t *)data;

    // Immediately capture arrival time if in test mode
    struct timespec arrival_time;
    if (ctx->cfg->test_mode) {
        clock_gettime(CLOCK_REALTIME, &arrival_time);
        atomic_fetch_add(&ctx->test_stats->total_events, 1);
    }

    // Filter by source IP range (if specified)
    if (ctx->cfg->src_range) {
        struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        if (!ip_in_range(src_ip, ctx->cfg->src_range)) {
            if (ctx->cfg->debug_enabled) {
                log_with_timestamp("[DEBUG] Event ignored: src_ip %s not in range %s\n", src_ip, ctx->cfg->src_range);
            }
            return NFCT_CB_CONTINUE;
        }
    }

    // Allocate and populate event_data_t
    event_data_t *event = malloc(sizeof(event_data_t));
    if (!event) {
        log_with_timestamp("[ERROR] Failed to allocate event_data_t\n");
        return NFCT_CB_CONTINUE;
    }

    // Store arrival time
    if (ctx->cfg->test_mode) {
        event->arrival_ts = arrival_time;
    } else {
        event->arrival_ts.tv_sec = 0;
        event->arrival_ts.tv_nsec = 0;
    }

    // Standard timestamp for normal usage
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

    // Attempt to enqueue event in event_queue immediately
    if (spsc_queue_push(ctx->event_queue, event) != 0) {
        if (atomic_exchange(&event_overflow_reported, 1) == 0) {
            log_with_timestamp("[WARNING] event_queue OVERFLOW: events are being dropped!\n");
        }
        nfct_destroy(event->ct);
        free(event);
    } else {
        atomic_store(&event_overflow_reported, 0);
        if (ctx->cfg->debug_enabled) {
            log_with_timestamp("[DEBUG] Event enqueued to event_queue immediately\n");
        }
    }

    return NFCT_CB_CONTINUE;
}

// ----------- SYSLOG CONNECTION WITH RETRY ----------------------
static int connect_to_syslog_with_retry(const char *host, const char *port_str, int *consecutive_failures) {
    struct addrinfo hints, *res, *rp;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        log_with_timestamp("[ERROR] getaddrinfo failed for %s:%s: %s\n", host, port_str, gai_strerror(err));
        (*consecutive_failures)++;
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;

        // Set socket options for better performance
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

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

    if (sock == -1) {
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", host, port_str);
        (*consecutive_failures)++;
    } else {
        log_with_timestamp("[INFO] Successfully connected to syslog server at %s:%s\n", host, port_str);
        *consecutive_failures = 0;
    }

    return sock;
}

// ----------- SYSLOG MESSAGE FORMAT ------------------
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data);
}

// ----------- FORMATTING THREAD ----------------------
void* formatting_thread(void* arg) {
    app_context_t *ctx = (app_context_t *)arg;

    while (!shutdown_flag) {
        void *item;
        if (spsc_queue_try_pop(ctx->event_queue, &item)) {
            event_data_t *event_data = (event_data_t *)item;
            
            // Measure time from arrival to formatting in test mode
            if (ctx->cfg->test_mode && event_data->arrival_ts.tv_sec > 0) {
                struct timespec now_ts;
                clock_gettime(CLOCK_REALTIME, &now_ts);
                long long arrival_ns = (long long)event_data->arrival_ts.tv_sec * 1000000000LL + 
                                      event_data->arrival_ts.tv_nsec;
                long long now_ns = (long long)now_ts.tv_sec * 1000000000LL + now_ts.tv_nsec;
                long long diff_ns = now_ns - arrival_ns;
                
                update_format_timing(ctx->test_stats, diff_ns);
                
                if (ctx->cfg->debug_enabled) {
                    log_with_timestamp("[TEST] Arrival to formatting: %lld ns (%.3f µs)\n", 
                                      diff_ns, diff_ns / 1000.0);
                }
            }

            conn_event_t event;
            memset(&event, 0, sizeof(conn_event_t));

            extract_conn_event(
                event_data->ct, event_data->type, &event,
                ctx->cfg->count_enabled, ctx->cfg->hash_enabled,
                ctx->cfg->payload_enabled, event_data->count, event_data->timestamp_ns,
                ctx->cfg->test_mode ? &event_data->arrival_ts : NULL
            );

            char buffer[MAX_MESSAGE_LEN] = {0};
            char *ptr = buffer;
            size_t remaining = sizeof(buffer);

            if (ctx->cfg->count_enabled) {
                ptr += snprintf(ptr, remaining, "%lld,", event.count);
                remaining = sizeof(buffer) - (ptr - buffer);
            }
            ptr += snprintf(ptr, remaining, "%lld", event.timestamp_ns);
            remaining = sizeof(buffer) - (ptr - buffer);

            if (ctx->cfg->hash_enabled || ctx->cfg->payload_enabled) {
                ptr += snprintf(ptr, remaining, ",");
                remaining = sizeof(buffer) - (ptr - buffer);
            }
            if (ctx->cfg->hash_enabled) {
                ptr += snprintf(ptr, remaining, "%s", event.hash);
                remaining = sizeof(buffer) - (ptr - buffer);
                if (ctx->cfg->payload_enabled) {
                    ptr += snprintf(ptr, remaining, ",");
                    remaining = sizeof(buffer) - (ptr - buffer);
                }
            }
            if (ctx->cfg->payload_enabled) {
                ptr += snprintf(
                    ptr, remaining, "%d,%d,%d,%s,%u,%s,%u",
                    event.type_num, event.state_num, event.proto_num,
                    event.src_ip, event.src_port, event.dst_ip, event.dst_port
                );
            }

            if (ctx->cfg->debug_enabled) {
                log_with_timestamp("[DEBUG] Formatting thread: Formatted event: %s\n", buffer);
            }

            // Create a message with arrival timestamp for test mode
            typedef struct {
                char *data;
                struct timespec arrival_ts;
            } formatted_msg_t;

            formatted_msg_t *formatted_msg = malloc(sizeof(formatted_msg_t));
            if (formatted_msg) {
                formatted_msg->data = strdup(buffer);
                if (ctx->cfg->test_mode && event_data->arrival_ts.tv_sec > 0) {
                    formatted_msg->arrival_ts = event_data->arrival_ts;
                } else {
                    formatted_msg->arrival_ts.tv_sec = 0;
                    formatted_msg->arrival_ts.tv_nsec = 0;
                }

                if (spsc_queue_push(ctx->syslog_queue, formatted_msg) != 0) {
                    if (atomic_exchange(&syslog_overflow_reported, 1) == 0) {
                        log_with_timestamp("[WARNING] syslog_queue OVERFLOW: formatted messages are being dropped!\n");
                    }
                    free(formatted_msg->data);
                    free(formatted_msg);
                } else {
                    atomic_store(&syslog_overflow_reported, 0);
                    if (ctx->cfg->debug_enabled) {
                        log_with_timestamp("[DEBUG] Formatting thread: Message enqueued to syslog_queue\n");
                    }
                }
            } else {
                log_with_timestamp("[ERROR] Formatting thread: Failed to allocate formatted message\n");
            }

            nfct_destroy(event_data->ct);
            free(event_data);
        } else {
            if (ctx->cfg->debug_enabled) {
                log_with_timestamp("[DEBUG] Formatting thread: No data dequeued, sleeping...\n");
            }
            usleep(1000);
        }
    }
    log_with_timestamp("[INFO] Formatting thread exiting by shutdown request\n");
    return NULL;
}

// ----------- IMPROVED SYSLOG THREAD WITH 500KB BUFFER AND 1S TIMEOUT --------------------------
void* syslog_thread(void* arg) {
    syslog_data_t *sdata = (syslog_data_t *)arg;
    void *buffer = NULL;
    char *batch = malloc(MAX_BUFFER_SIZE);  // 500KB buffer
    char *lost_batch = NULL;
    int message_count = 0;
    size_t batch_size = 0;
    struct timeval last_sent, now;
    gettimeofday(&last_sent, NULL);

    if (!batch) {
        log_with_timestamp("[ERROR] Failed to allocate batch buffer of %d bytes\n", MAX_BUFFER_SIZE);
        return NULL;
    }
    batch[0] = '\0';

    log_with_timestamp("[INFO] Syslog thread started with %dKB buffer and %dms timeout. Waiting for events...\n",
                     MAX_BUFFER_SIZE/1024, BATCH_TIMEOUT_US/1000);

    while (!shutdown_flag) {
        gettimeofday(&now, NULL);
        long elapsed_us = (now.tv_sec - last_sent.tv_sec) * 1000000 + (now.tv_usec - last_sent.tv_usec);

        // Send batch due to timeout (1s) - reduced from 20s
        if (message_count > 0 && elapsed_us >= BATCH_TIMEOUT_US) {
            log_with_timestamp(
                "[INFO] Syslog thread: Sending batch due to 1s timeout - %d messages, %zu bytes (elapsed: %.3fs)\n",
                message_count, batch_size, elapsed_us / 1000000.0
            );
            goto send_batch;
        }

        // Adaptive batch sizing based on queue utilization
        int current_batch_size = MIN_BATCH_SIZE;
        if (ADAPTIVE_BATCH_SIZE) {
            double queue_util = spsc_queue_utilization(sdata->queue);
            if (queue_util > 0.3) current_batch_size = MIN_BATCH_SIZE * 2;
            if (queue_util > 0.6) current_batch_size = MIN_BATCH_SIZE * 5;
            if (queue_util > 0.8) current_batch_size = MAX_BATCH_SIZE;
        }

        // Send batch due to reaching batch size
        if (message_count >= current_batch_size) {
            log_with_timestamp(
                "[INFO] Syslog thread: Sending batch due to size - %d messages, %zu bytes\n",
                message_count, batch_size
            );
            goto send_batch;
        }

        // Try to dequeue a formatted message
        if (spsc_queue_try_pop(sdata->queue, &buffer)) {
            typedef struct {
                char *data;
                struct timespec arrival_ts;
            } formatted_msg_t;

            formatted_msg_t *formatted_msg = (formatted_msg_t *)buffer;

            if (sdata->debug_enabled) {
                log_with_timestamp("[DEBUG] Syslog thread: Dequeued buffer: %s\n", formatted_msg->data);
            }

            // Measure time from arrival to syslog in test mode
            if (sdata->test_mode && formatted_msg->arrival_ts.tv_sec > 0) {
                struct timespec now_ts;
                clock_gettime(CLOCK_REALTIME, &now_ts);
                long long arrival_ns = (long long)formatted_msg->arrival_ts.tv_sec * 1000000000LL + 
                                      formatted_msg->arrival_ts.tv_nsec;
                long long now_ns = (long long)now_ts.tv_sec * 1000000000LL + now_ts.tv_nsec;
                long long diff_ns = now_ns - arrival_ns;
                
                update_syslog_timing(sdata->test_stats, diff_ns);
                
                if (sdata->debug_enabled) {
                    log_with_timestamp("[TEST] Arrival to syslog: %lld ns (%.3f µs)\n", 
                                      diff_ns, diff_ns / 1000.0);
                }
            }

            char syslog_msg[MAX_MESSAGE_LEN];
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, formatted_msg->data);

            size_t msg_len = strlen(syslog_msg);

            // Check if adding this message would exceed 500KB buffer
            if (batch_size + msg_len + 2 < MAX_BUFFER_SIZE) {
                strcat(batch, syslog_msg);
                strcat(batch, "\n");
                batch_size += msg_len + 1; // +1 for newline
                message_count++;
                
                if (sdata->debug_enabled) {
                    log_with_timestamp("[DEBUG] Added message to batch: count=%d, size=%zu bytes\n", 
                                     message_count, batch_size);
                }
            } else {
                // Send current batch due to buffer size limit
                log_with_timestamp("[INFO] Buffer size limit reached (%zu bytes), sending batch with %d messages\n", 
                                 batch_size, message_count);
                goto send_batch_and_continue;
            }

            free(formatted_msg->data);
            free(formatted_msg);
            buffer = NULL;
        } else {
            usleep(1000);  // Sleep 1ms when no data
            continue;
        }
        continue;

    send_batch_and_continue:
        // Send current batch, then add the pending message to new batch
        goto send_batch;

    send_batch:;
        int failures = atomic_load(&sdata->consecutive_failures);
        if (failures >= MAX_CONSECUTIVE_FAILURES) {
            int delay_ms = RECONNECT_DELAY_MS * (1 << (failures - MAX_CONSECUTIVE_FAILURES));
            if (delay_ms > 30000) delay_ms = 30000;
            log_with_timestamp("[INFO] Too many consecutive failures, backing off for %d ms\n", delay_ms);
            usleep(delay_ms * 1000);
        }

        // Try to connect if we don't have a connection
        if (sdata->syslog_fd < 0) {
            sdata->syslog_fd = connect_to_syslog_with_retry(sdata->syslog_ip, SYSLOG_PORT, 
                                                          &sdata->consecutive_failures);
            atomic_store(&sdata->consecutive_failures, failures);
        }

        int sent_ok = 0;
        if (sdata->syslog_fd >= 0) {
            ssize_t sent = send(sdata->syslog_fd, batch, batch_size, MSG_NOSIGNAL);
            if (sent > 0) {
                atomic_fetch_add(&sdata->bytes_transferred, sent);
                log_with_timestamp(
                    "[INFO] Syslog thread: Successfully sent %zd bytes to syslog. Total transferred: %zu bytes\n",
                    sent, atomic_load(&sdata->bytes_transferred)
                );
                sent_ok = 1;
                atomic_store(&sdata->consecutive_failures, 0);
            } else {
                log_with_timestamp("[ERROR] Syslog thread: Failed to send to syslog: %s\n", strerror(errno));
                close(sdata->syslog_fd);
                sdata->syslog_fd = -1;
                atomic_fetch_add(&sdata->consecutive_failures, 1);
            }
        }

        free(lost_batch);
        if (sent_ok) {
            lost_batch = NULL;
        } else {
            lost_batch = strdup(batch);
            if (!lost_batch) {
                log_with_timestamp("[ERROR] Syslog thread: Failed to save lost batch\n");
            } else {
                log_with_timestamp("[INFO] Syslog thread: Saved %zu bytes for retry\n", batch_size);
            }
        }

        // Reset for next batch
        batch[0] = '\0';
        batch_size = 0;
        message_count = 0;
        gettimeofday(&last_sent, NULL);

        if (buffer) {
            typedef struct {
                char *data;
                struct timespec arrival_ts;
            } formatted_msg_t;

            formatted_msg_t *formatted_msg = (formatted_msg_t *)buffer;
            char syslog_msg[MAX_MESSAGE_LEN];
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, formatted_msg->data);
            strcat(batch, syslog_msg);
            strcat(batch, "\n");
            batch_size = strlen(syslog_msg) + 1; // +1 for newline
            message_count = 1;
            free(formatted_msg->data);
            free(formatted_msg);
            buffer = NULL;
        }
    }

    free(batch);
    if (lost_batch) free(lost_batch);
    log_with_timestamp("[INFO] Syslog thread exiting by shutdown request\n");
    return NULL;
}

// ----------- CONNECTION MONITOR THREAD --------------
void* connection_monitor_thread(void* arg) {
    syslog_data_t *sdata = (syslog_data_t *)arg;
    
    while (!shutdown_flag) {
        sleep(5); // Check every 5 seconds
        
        if (sdata->syslog_fd < 0) {
            log_with_timestamp("[WARNING] Not connected to syslog server, attempting reconnection\n");
            int failures = atomic_load(&sdata->consecutive_failures);
            sdata->syslog_fd = connect_to_syslog_with_retry(sdata->syslog_ip, SYSLOG_PORT, &failures);
            atomic_store(&sdata->consecutive_failures, failures);
        } 
    }
    
    return NULL;
}

// ----------- STATS PRINTING THREAD ------------------
void* stats_thread(void* arg) {
    test_stats_t *stats = (test_stats_t *)arg;
    
    while (!shutdown_flag) {
        sleep(5);  // Print stats every 5 seconds
        if (!shutdown_flag) {
            print_test_stats(stats);
        }
    }
    
    return NULL;
}

// ----------- MAIN FUNCTION WITH EPOLL --------------------------
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

    // Initialize test statistics if in test mode
    if (cfg.test_mode) {
        init_test_stats(&global_test_stats);
        log_with_timestamp("[INFO] Test mode enabled - measuring event processing times\n");
    }

    log_with_timestamp("[INFO] Initializing with event_queue_size=%zu, syslog_queue_size=%zu\n",
                       cfg.event_queue_size, cfg.syslog_queue_size);
    log_with_timestamp("[INFO] Buffer size: %dKB, Timeout: %dms\n", 
                     MAX_BUFFER_SIZE/1024, BATCH_TIMEOUT_US/1000);

    // Initialize SPSC queues with dynamic resizing capability
    spsc_queue_t *event_queue = spsc_queue_init(cfg.event_queue_size);
    if (!event_queue) {
        log_with_timestamp("[ERROR] Failed to initialize event_queue\n");
        return 1;
    }
    spsc_queue_t *syslog_queue = spsc_queue_init(cfg.syslog_queue_size);
    if (!syslog_queue) {
        log_with_timestamp("[ERROR] Failed to initialize syslog_queue\n");
        spsc_queue_destroy(event_queue);
        return 1;
    }

    app_context_t ctx = {
        .event_queue = event_queue,
        .syslog_queue = syslog_queue,
        .cfg = &cfg,
        .test_stats = &global_test_stats
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
        .bytes_transferred = 0,
        .consecutive_failures = 0,
        .test_stats = &global_test_stats,
        .test_mode = cfg.test_mode
    };

    pthread_t syslog_tid;
    if (pthread_create(&syslog_tid, NULL, syslog_thread, &sdata) != 0) {
        log_with_timestamp("[ERROR] Failed to create syslog thread\n");
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    // Create connection monitor thread
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, connection_monitor_thread, &sdata) != 0) {
        log_with_timestamp("[WARNING] Failed to create connection monitor thread\n");
    } else {
        log_with_timestamp("[INFO] Connection monitor thread started\n");
    }

    // Create stats thread for test mode
    pthread_t stats_tid;
    if (cfg.test_mode) {
        if (pthread_create(&stats_tid, NULL, stats_thread, &global_test_stats) != 0) {
            log_with_timestamp("[WARNING] Failed to create stats thread\n");
        }
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

    // Get nfct file descriptor
    int conntrack_fd = nfct_fd(g_nfct_handle);
    if (conntrack_fd < 0) {
        log_with_timestamp("[ERROR] Failed to get nfct file descriptor\n");
        nfct_close(g_nfct_handle);
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    // Set nfct fd to non-blocking mode
    int flags = fcntl(conntrack_fd, F_GETFL, 0);
    if (flags == -1 || fcntl(conntrack_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_with_timestamp("[ERROR] Failed to set O_NONBLOCK on nfct fd: %s\n", strerror(errno));
        nfct_close(g_nfct_handle);
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    // Create epoll instance
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        log_with_timestamp("[ERROR] Failed to create epoll instance: %s\n", strerror(errno));
        nfct_close(g_nfct_handle);
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    // Add conntrack_fd to epoll with level-triggered mode (no EPOLLET)
    struct epoll_event ev;
    ev.events = EPOLLIN;  // Level-triggered mode
    ev.data.fd = conntrack_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conntrack_fd, &ev) < 0) {
        log_with_timestamp("[ERROR] Failed to add conntrack_fd to epoll: %s\n", strerror(errno));
        close(epoll_fd);
        nfct_close(g_nfct_handle);
        spsc_queue_destroy(event_queue);
        spsc_queue_destroy(syslog_queue);
        return 1;
    }

    log_with_timestamp("[INFO] Starting to catch conntrack events using epoll\n");


       // Improved epoll-based event loop
    struct epoll_event events[64];  // Process more events per epoll_wait
    const int epoll_timeout_ms = 10;  // More responsive timeout (10ms)
    int event_count = 0;
    int event_burst_limit = 1000;  // Max events to process before yielding

    while (!shutdown_flag) {
        int nfds = epoll_wait(epoll_fd, events, 64, epoll_timeout_ms);
        
        if (nfds < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check shutdown flag
                continue;
            }
            log_with_timestamp("[ERROR] epoll_wait failed: %s\n", strerror(errno));
            break;
        }
        
        if (nfds == 0) {
            // No events, yield to other threads
            sched_yield();
            continue;
        }
        
        // Process events with controlled batching
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == conntrack_fd) {
                if (events[i].events & EPOLLIN) {
                    // Process events in a controlled burst to avoid starving other threads
                    event_count = 0;
                    while (!shutdown_flag) {
                        int ret = nfct_catch(g_nfct_handle);
                        if (ret < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // No more events available right now
                                break;
                            }
                            if (errno == EINTR) {
                                // Interrupted, try again
                                continue;
                            }
                            
                            log_with_timestamp("[ERROR] nfct_catch failed: %s\n", strerror(errno));
                            if (errno != ENOBUFS) {  // ENOBUFS can happen under load, don't exit
                                shutdown_flag = 1;
                            }
                            break;
                        }
                        
                        // Successfully processed an event
                        event_count++;
                        
                        // Yield to other threads after processing many events
                        if (event_count >= event_burst_limit) {
                            if (cfg.debug_enabled) {
                                log_with_timestamp("[DEBUG] Processed %d events, yielding to other threads\n", 
                                                 event_count);
                            }
                            sched_yield();
                            break;  // Exit this burst and let epoll_wait check for more events
                        }
                    }
                }
                
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    log_with_timestamp("[ERROR] Error condition on conntrack_fd\n");
                    shutdown_flag = 1;
                    break;
                }
            }
        }
        
        // Periodically yield to ensure syslog thread gets CPU time
        if (event_count > 0) {
            sched_yield();
        }
    }

    // Cleanup
    log_with_timestamp("[INFO] Exiting, cleaning up...\n");
    
    close(epoll_fd);
    
    if (g_nfct_handle) {
        nfct_close(g_nfct_handle);
        g_nfct_handle = NULL;
    }
    
    pthread_join(formatting_tid, NULL);
    pthread_join(syslog_tid, NULL);
    pthread_join(monitor_tid, NULL);
    
    if (cfg.test_mode) {
        pthread_join(stats_tid, NULL);
        // Print final statistics
        log_with_timestamp("[INFO] Final test statistics:\n");
        print_test_stats(&global_test_stats);
    }
    
    spsc_queue_destroy(event_queue);
    spsc_queue_destroy(syslog_queue);
    
    if (sdata.syslog_fd >= 0) close(sdata.syslog_fd);
    
    log_with_timestamp("[INFO] Exiting, final close\n");
    
    return 0;
}
