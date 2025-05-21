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

// Include SPSC queue header (assumed to be available)
#include "spsc_queue.h"

#define MAX_MESSAGE_LEN 2048    // Maximum length of a single syslog message
#define SYSLOG_PORT "514"       // Syslog server port
#define MIN_BATCH_SIZE 5        // Minimum number of messages to batch before sending
#define BATCH_TIMEOUT_US 1000000 // Timeout in microseconds to flush batch
#define LOGFILE_PATH "/var/log/conntrack_logger.log" // Log file path for daemon mode

// Configuration structure to hold command-line options
struct config {
    char *syslog_ip;        // IP address of the syslog server
    char *machine_name;     // Machine name for syslog messages
    int daemonize;          // Flag to run as a daemon
    int kill_daemons;       // Flag to kill existing daemons
    int count_enabled;      // Flag to include event count
    int debug_enabled;      // Flag to enable debug logging
    int hash_enabled;       // Flag to include BLAKE3 hash
    int payload_enabled;    // Flag to include detailed payload
    char *src_range;        // Source IP range for filtering (CIDR)
};

// Updated connection event structure to hold raw data
struct conn_event {
    long long count;        // Event count (if enabled)
    long long timestamp_ns; // Timestamp in nanoseconds from CLOCK_REALTIME
    uint32_t src_ip;        // Source IP address (raw uint32_t)
    uint32_t dst_ip;        // Destination IP address (raw uint32_t)
    uint16_t src_port;      // Source port number
    uint16_t dst_port;      // Destination port number
    uint8_t proto_num;      // Protocol number (e.g., IPPROTO_TCP)
    enum nf_conntrack_msg_type type; // Message type (NEW, UPDATE, DESTROY)
    int state_num;          // TCP state number (-1 if not TCP or unset)
    uint32_t timeout;       // Connection timeout in seconds
    uint32_t status;        // Connection status flags (e.g., IPS_ASSURED)
};

// Callback data for the conntrack event handler
struct callback_data {
    spsc_queue_t *queue;    // Pointer to the SPSC queue
    atomic_int *overflow_flag; // Flag to track queue overflow
    int count_enabled;      // Flag to include event count
    int hash_enabled;       // Flag to include hash
    int payload_enabled;    // Flag to include payload
    atomic_llong *event_counter; // Atomic counter for events
    const char *src_range;  // Source IP range for filtering
};

// Syslog thread data
struct syslog_data {
    spsc_queue_t *queue;    // Pointer to the SPSC queue
    char *syslog_ip;        // Syslog server IP
    int syslog_fd;          // File descriptor for syslog connection
    char *machine_name;     // Machine name for syslog messages
    int count_enabled;      // Flag to include event count
    int debug_enabled;      // Flag to enable debug logging
    int hash_enabled;       // Flag to include hash
    int payload_enabled;    // Flag to include payload
    atomic_size_t *bytes_transferred; // Total bytes sent to syslog
    atomic_int *overflow_flag; // Flag to track queue overflow
};

static int global_debug_enabled = 0; // Global debug flag

// Log messages with a timestamp
void log_with_timestamp(const char *fmt, ...) {
    int is_debug = (strncmp(fmt, "[DEBUG]", 7) == 0); // Check if message is debug
    if (is_debug && !global_debug_enabled) return;   // Skip debug messages if not enabled

    struct timeval tv;                               // Structure for current time
    gettimeofday(&tv, NULL);                         // Get current time
    struct tm tm;                                    // Structure for broken-down time
    localtime_r(&tv.tv_sec, &tm);                    // Convert to local time

    char timestr[64];                                // Buffer for timestamp string
    strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", &tm); // Format timestamp

    fprintf(stdout, "[%s.%03ld] ", timestr, tv.tv_usec / 1000); // Print timestamp with milliseconds

    va_list args;                                    // Variable argument list
    va_start(args, fmt);                             // Initialize argument list
    vfprintf(stdout, fmt, args);                     // Print formatted message
    va_end(args);                                    // Clean up argument list
    fflush(stdout);                                  // Flush output buffer
}

// Print usage help
static void print_help(const char *progname) {
    printf("Usage: %s [options]\n", progname);       // Show program usage
    printf("Options:\n");                           // List available options
    printf("  -h, --help                Show this help message\n");
    printf("  -n, --machine-name <name> Specify machine name (required)\n");
    printf("  -l, --lsip <ip_address>   Specify syslog server IP/domain (required)\n");
    printf("  -d, --daemonize           Daemonize the program (optional)\n");
    printf("  -k, --kill                Kill all running daemons (optional)\n");
    printf("  -c, --count <yes|no>      Prepend event count to each event (optional)\n");
    printf("  -D, --debug               Enable debug logging (optional)\n");
    printf("  -H, --hash                Include BLAKE3 hash in log messages\n");
    printf("  -P, --payload             Include detailed payload tuple\n");
    printf("  -r, --src-range <range>   Filter events by source IP range (CIDR)\n");
    printf("Note: At least one of -H or -P must be specified.\n");
}

// Parse command-line arguments into config structure
static int parse_config(int argc, char *argv[], struct config *cfg) {
    static struct option long_options[] = {         // Define long options
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
    int opt;                                        // Option character
    cfg->syslog_ip = NULL;                          // Initialize syslog IP
    cfg->machine_name = NULL;                       // Initialize machine name
    cfg->daemonize = 0;                             // Default: no daemon
    cfg->kill_daemons = 0;                          // Default: don’t kill daemons
    cfg->count_enabled = 0;                         // Default: no event count
    cfg->debug_enabled = 0;                         // Default: no debug
    cfg->hash_enabled = 0;                          // Default: no hash
    cfg->payload_enabled = 0;                       // Default: no payload
    cfg->src_range = NULL;                          // Default: no IP range filter

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:DHPr:", long_options, NULL)) != -1) { // Parse options
        switch (opt) {
            case 'h': print_help(argv[0]); exit(0); // Show help and exit
            case 'n': cfg->machine_name = optarg; break; // Set machine name
            case 'l': cfg->syslog_ip = optarg; break; // Set syslog IP
            case 'd': cfg->daemonize = 1; break;    // Enable daemon mode
            case 'k': cfg->kill_daemons = 1; break; // Enable kill daemons
            case 'c':                               // Set count option
                if (strcasecmp(optarg, "yes") == 0) cfg->count_enabled = 1;
                else cfg->count_enabled = 0;
                break;
            case 'D': cfg->debug_enabled = 1; break; // Enable debug
            case 'H': cfg->hash_enabled = 1; break;  // Enable hash
            case 'P': cfg->payload_enabled = 1; break; // Enable payload
            case 'r': cfg->src_range = optarg; break; // Set source IP range
            default: print_help(argv[0]); return 1;  // Invalid option, show help
        }
    }

    if (!cfg->kill_daemons && (!cfg->syslog_ip || !cfg->machine_name)) { // Check required args
        log_with_timestamp("Syslog server IP/domain and machine name are required\n");
        print_help(argv[0]);
        return 1;
    }
    return 0;                                       // Success
}

static atomic_llong event_counter = 0;              // Global event counter

// Check if an IP is within a CIDR range
int ip_in_range(const char *ip_str, const char *range) {
    struct in_addr ip;                              // Structure for IP address
    if (inet_pton(AF_INET, ip_str, &ip) <= 0) return 0; // Convert string IP to binary, fail if invalid

    char *range_copy = strdup(range);               // Copy range for modification
    char *slash = strchr(range_copy, '/');          // Find CIDR separator
    if (!slash) {                                   // No CIDR mask
        free(range_copy);
        return 0;
    }
    *slash = '\0';                                  // Split network and prefix
    int prefix = atoi(slash + 1);                   // Parse prefix length
    if (prefix < 0 || prefix > 32) {                // Validate prefix
        free(range_copy);
        return 0;
    }

    struct in_addr network;                         // Structure for network address
    if (inet_pton(AF_INET, range_copy, &network) <= 0) { // Convert network string to binary
        free(range_copy);
        return 0;
    }

    uint32_t ip_num = ntohl(ip.s_addr);             // Convert IP to host byte order
    uint32_t net_num = ntohl(network.s_addr);       // Convert network to host byte order
    uint32_t mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF; // Calculate subnet mask
    free(range_copy);                               // Free duplicated string

    return (ip_num & mask) == (net_num & mask);     // Check if IP is in range
}

// Calculate BLAKE3 hash (64-bit output)
static void calculate_hash(const char *input, char *output) {
    unsigned char hash[8];                          // Buffer for 8-byte hash
    blake3_hasher hasher;                           // BLAKE3 hasher context
    blake3_hasher_init(&hasher);                    // Initialize hasher
    blake3_hasher_update(&hasher, input, strlen(input)); // Update hasher with input
    blake3_hasher_finalize(&hasher, hash, 8);       // Finalize hash (8 bytes)
    for (int i = 0; i < 8; i++) {                   // Convert to hex string
        sprintf(output + (i * 2), "%02x", hash[i]); // Two hex chars per byte
    }
    output[16] = '\0';                              // Null-terminate string
}

// Extract raw connection event data
static void extract_conn_event(struct nf_conntrack *ct, enum nf_conntrack_msg_type type,
                               struct conn_event *event, int count_enabled,
                               atomic_llong *event_counter) {
    struct timespec ts;                             // Timespec for timestamp
    clock_gettime(CLOCK_REALTIME, &ts);             // Get current time with CLOCK_REALTIME
    event->timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec; // Convert to nanoseconds

    if (count_enabled) {                            // If counting is enabled
        event->count = atomic_fetch_add(event_counter, 1) + 1; // Increment and get count
    } else {
        event->count = 0;                           // No count
    }

    event->src_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC); // Get raw source IP
    event->dst_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST); // Get raw destination IP
    event->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? // Get source port if set
                      ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    event->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? // Get dest port if set
                      ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;
    event->proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO); // Get protocol number
    event->type = type;                             // Set message type
    if (event->proto_num == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) { // TCP state
        event->state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE); // Get TCP state
    } else {
        event->state_num = -1;                      // No state for non-TCP
    }
    event->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? // Get timeout if set
                     nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;
    event->status = nfct_attr_is_set(ct, ATTR_STATUS) ? // Get status if set
                    nfct_get_attr_u32(ct, ATTR_STATUS) : 0;
}

// Conntrack event callback (main thread)
static int event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct callback_data *cb_data = (struct callback_data *)data; // Cast callback data
    struct conn_event *event = malloc(sizeof(struct conn_event)); // Allocate event structure
    if (!event) {                                         // Check allocation failure
        log_with_timestamp("[ERROR] Failed to allocate memory for conn_event\n");
        return NFCT_CB_CONTINUE;                          // Continue processing
    }
    extract_conn_event(ct, type, event, cb_data->count_enabled, cb_data->event_counter); // Extract data

    // Convert source IP to string for filtering
    char src_ip_str[INET_ADDRSTRLEN];                     // Buffer for source IP string
    struct in_addr src_addr = { .s_addr = event->src_ip }; // Source IP structure
    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN); // Convert to string
    if (cb_data->src_range && !ip_in_range(src_ip_str, cb_data->src_range)) { // Filter by range
        free(event);                                      // Free event if filtered out
        return NFCT_CB_CONTINUE;                          // Continue processing
    }

    if (!spsc_queue_enqueue(cb_data->queue, event)) {     // Enqueue event pointer
        if (atomic_exchange(cb_data->overflow_flag, 1) == 0) { // Check and set overflow
            log_with_timestamp("[WARNING] SPSC queue overflow: events are being dropped!\n");
        }
        free(event);                                      // Free event on failure
    } else {
        if (atomic_exchange(cb_data->overflow_flag, 0) == 1) { // Clear overflow flag
            log_with_timestamp("[INFO] SPSC queue returned to normal: events are no longer being dropped.\n");
        }
    }

    log_with_timestamp("[DEBUG] Successfully enqueued event\n"); // Log success
    return NFCT_CB_CONTINUE;                              // Continue processing
}

// Connect to syslog server
static int connect_to_syslog(const char *host, const char *port_str) {
    struct addrinfo hints, *res, *rp;                     // Address info structures
    int sock = -1;                                        // Socket file descriptor

    memset(&hints, 0, sizeof(hints));                     // Clear hints
    hints.ai_family = AF_UNSPEC;                          // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;                      // TCP socket

    int err = getaddrinfo(host, port_str, &hints, &res);  // Resolve hostname
    if (err != 0) {                                       // Check for error
        log_with_timestamp("[ERROR] getaddrinfo failed for %s:%s: %s\n", host, port_str, gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {        // Try each address
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); // Create socket
        if (sock == -1) continue;                         // Skip on failure

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break; // Connect succeeded

        close(sock);                                      // Close failed socket
        sock = -1;                                        // Reset socket
    }

    freeaddrinfo(res);                                    // Free address info

    if (sock == -1) {                                     // No connection made
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", host, port_str);
    } else {
        log_with_timestamp("[INFO] Successfully connected to syslog server at %s:%s\n", host, port_str);
    }

    return sock;                                          // Return socket FD
}

// Format protocol string
static const char *get_protocol_str(uint8_t proto_num) {
    switch (proto_num) {                                  // Map protocol number to string
        case IPPROTO_TCP: return "tcp";                   // TCP protocol
        case IPPROTO_UDP: return "udp";                   // UDP protocol
        default: return "unknown";                        // Unknown protocol
    }
}

// Format message type string
static const char *get_msg_type_str(enum nf_conntrack_msg_type type) {
    switch (type) {                                       // Map type to string
        case NFCT_T_NEW: return "NEW";                    // New connection
        case NFCT_T_UPDATE: return "UPDATE";              // Updated connection
        case NFCT_T_DESTROY: return "DESTROY";            // Destroyed connection
        default: return "UNKNOWN";                        // Unknown type
    }
}

// Format TCP state string
static const char *get_state_str(int state_num) {
    switch (state_num) {                                  // Map TCP state to string
        case 0: return "NONE";                            // No state
        case 1: return "SYN_SENT";                        // SYN sent
        case 2: return "SYN_RECV";                        // SYN received
        case 3: return "ESTABLISHED";                     // Connection established
        case 4: return "FIN_WAIT";                        // FIN wait
        case 5: return "CLOSE_WAIT";                      // Close wait
        case 6: return "LAST_ACK";                        // Last ACK
        case 7: return "TIME_WAIT";                       // Time wait
        case 8: return "CLOSE";                           // Closed
        default: return "UNKNOWN";                        // Unknown state
    }
}

// Format assured status string
static const char *get_assured_str(uint32_t status) {
    return (status & IPS_ASSURED) ? "ASSURED" : "N/A";    // Check if connection is assured
}

// Format syslog message
static void create_syslog_message(char *msg, size_t len, const char *machine_name, const char *data) {
    snprintf(msg, len, "<134> %s conntrack_logger - - - %s", machine_name, data); // Format syslog message
}

// Syslog thread to process events
static void *syslog_thread(void *arg) {
    struct syslog_data *sdata = (struct syslog_data *)arg; // Cast thread data
    struct conn_event *event = NULL;                      // Pointer to dequeued event
    char batch[MAX_MESSAGE_LEN * MIN_BATCH_SIZE] = "";    // Batch buffer for messages
    int message_count = 0;                                // Number of messages in batch
    struct timeval last_sent, now;                        // Timestamps for batch timing
    gettimeofday(&last_sent, NULL);                       // Initialize last sent time

    log_with_timestamp("[INFO] Syslog thread started. Waiting for events...\n"); // Log thread start

    while (1) {                                           // Infinite loop
        gettimeofday(&now, NULL);                         // Get current time
        long elapsed_us = (now.tv_sec - last_sent.tv_sec) * 1000000 + // Calculate elapsed time
                          (now.tv_usec - last_sent.tv_usec);
        if (message_count > 0 && elapsed_us >= BATCH_TIMEOUT_US) { // Check timeout
            if (sdata->debug_enabled) {                   // Log timeout if debug enabled
                log_with_timestamp("[DEBUG] Timeout reached, sending %d messages\n", message_count);
            }
            goto send_batch;                              // Jump to send batch
        }

        if (spsc_queue_dequeue(sdata->queue, (void **)&event)) { // Dequeue event
            if (sdata->debug_enabled) {                   // Log dequeue if debug enabled
                log_with_timestamp("[DEBUG] Dequeued event\n");
            }

            // Format the event
            char buffer[1024] = {0};                      // Buffer for formatted event
            char *ptr = buffer;                           // Pointer into buffer
            size_t remaining = sizeof(buffer);            // Remaining space in buffer

            if (sdata->count_enabled) {                   // Add count if enabled
                ptr += snprintf(ptr, remaining, "%lld,", event->count);
                remaining -= (ptr - buffer);
            }

            ptr += snprintf(ptr, remaining, "%lld", event->timestamp_ns); // Add timestamp
            remaining -= (ptr - buffer);

            // Convert IPs to strings
            char src_ip_str[INET_ADDRSTRLEN];             // Buffer for source IP
            char dst_ip_str[INET_ADDRSTRLEN];             // Buffer for dest IP
            struct in_addr src_addr = { .s_addr = event->src_ip }; // Source IP structure
            struct in_addr dst_addr = { .s_addr = event->dst_ip }; // Dest IP structure
            inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN); // Convert source IP
            inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN); // Convert dest IP

            // Get formatted strings
            const char *protocol_str = get_protocol_str(event->proto_num); // Protocol string
            const char *msg_type_str = get_msg_type_str(event->type); // Message type string
            const char *state_str = (event->proto_num == IPPROTO_TCP && event->state_num >= 0) ? // State string
                                    get_state_str(event->state_num) : "N/A";
            const char *assured_str = get_assured_str(event->status); // Assured status string

            // Calculate hash if enabled
            char hash_input[256];                         // Buffer for hash input
            char hash[17] = {0};                          // Buffer for hash output
            if (sdata->hash_enabled) {                    // If hash is enabled
                snprintf(hash_input, sizeof(hash_input), "%s,%s,%s,%s,%u,%u,%s", // Format hash input
                         protocol_str, state_str, src_ip_str, dst_ip_str,
                         event->src_port, event->dst_port, msg_type_str);
                calculate_hash(hash_input, hash);         // Compute hash
            }

            if (sdata->hash_enabled || sdata->payload_enabled) { // Add separator if needed
                ptr += snprintf(ptr, remaining, ",");
                remaining -= (ptr - buffer);
            }

            if (sdata->hash_enabled) {                    // Add hash if enabled
                ptr += snprintf(ptr, remaining, "%s", hash);
                remaining -= (ptr - buffer);
                if (sdata->payload_enabled) {             // Add separator if payload follows
                    ptr += snprintf(ptr, remaining, ",");
                    remaining -= (ptr - buffer);
                }
            }

            if (sdata->payload_enabled) {                 // Add payload if enabled
                ptr += snprintf(ptr, remaining, "%d,%d,%d,%s,%u,%s,%u", // Format payload
                                (int)event->type, event->state_num, event->proto_num,
                                src_ip_str, event->src_port, dst_ip_str, event->dst_port);
                remaining -= (ptr - buffer);
            }

            // Create and append syslog message
            char syslog_msg[MAX_MESSAGE_LEN];             // Buffer for syslog message
            create_syslog_message(syslog_msg, sizeof(syslog_msg), sdata->machine_name, buffer); // Format message
            strncat(batch, syslog_msg, sizeof(batch) - strlen(batch) - 1); // Append to batch
            strncat(batch, "\n", sizeof(batch) - strlen(batch) - 1); // Add newline
            message_count++;                              // Increment message count

            if (sdata->debug_enabled) {                   // Log batch addition if debug enabled
                log_with_timestamp("[DEBUG] Added message to batch, count: %d\n", message_count);
            }

            free(event);                                  // Free dequeued event
            event = NULL;                                 // Clear pointer
        } else {                                          // No event dequeued
            if (sdata->debug_enabled) {                   // Log sleep if debug enabled
                log_with_timestamp("[DEBUG] No data dequeued, sleeping...\n");
            }
            usleep(1000);                                 // Sleep briefly
            continue;                                     // Next iteration
        }

        if (message_count >= MIN_BATCH_SIZE) {            // Check batch size
            if (sdata->debug_enabled) {                   // Log batch send if debug enabled
                log_with_timestamp("[DEBUG] Batch size reached, sending %d messages\n", message_count);
            }
        send_batch:                                       // Label for sending batch
            if (sdata->debug_enabled) {                   // Log batch content if debug enabled
                log_with_timestamp("[DEBUG] Sending batch of %d messages: %s\n", message_count, batch);
            }
            if (sdata->syslog_fd < 0) {                   // Reconnect if socket closed
                sdata->syslog_fd = connect_to_syslog(sdata->syslog_ip, SYSLOG_PORT);
                if (sdata->syslog_fd < 0) {               // Check reconnection failure
                    log_with_timestamp("[ERROR] Failed to reconnect to syslog server\n");
                    batch[0] = '\0';                      // Clear batch
                    message_count = 0;                    // Reset count
                    gettimeofday(&last_sent, NULL);       // Reset timer
                    continue;                             // Next iteration
                }
            }
            ssize_t sent = send(sdata->syslog_fd, batch, strlen(batch), 0); // Send batch
            if (sent > 0) {                               // Check send success
                atomic_fetch_add(sdata->bytes_transferred, sent); // Update bytes transferred
                log_with_timestamp("[INFO] Sent %zd bytes to syslog. Total transferred: %zu bytes\n",
                                   sent, atomic_load(sdata->bytes_transferred)); // Log success
            } else {                                      // Handle send failure
                log_with_timestamp("[ERROR] Failed to send to syslog: %s\n", strerror(errno));
                close(sdata->syslog_fd);                  // Close socket
                sdata->syslog_fd = -1;                    // Mark as closed
            }
            batch[0] = '\0';                              // Clear batch
            message_count = 0;                            // Reset count
            gettimeofday(&last_sent, NULL);               // Update last sent time
        }
    }
    return NULL;                                          // Thread exit (unreachable)
}

// Kill running daemons
static void kill_all_daemons() {
    pid_t current_pid = getpid();                         // Get current process ID
    FILE *fp = popen("pidof conntrack_logger", "r");      // Run pidof to find PIDs
    if (!fp) {                                            // Check failure
        log_with_timestamp("Failed to run pidof\n");
        return;
    }
    char pid_str[16];                                     // Buffer for PID string
    while (fscanf(fp, "%s", pid_str) == 1) {              // Read each PID
        pid_t pid = atoi(pid_str);                        // Convert to integer
        if (pid != current_pid) {                         // Skip current process
            if (kill(pid, SIGTERM) == -1) {               // Send SIGTERM
                log_with_timestamp("Failed to kill process %d: %s\n", pid, strerror(errno));
            }
        }
    }
    pclose(fp);                                           // Close pipe
}

// Signal handler for clean shutdown
static void signal_handler(int sig) {
    log_with_timestamp("[INFO] Received signal %d, shutting down\n", sig); // Log signal
    exit(0);                                              // Exit program
}

// Main function
int main(int argc, char *argv[]) {
    struct config cfg;                                    // Configuration structure
    if (parse_config(argc, argv, &cfg)) return 1;         // Parse arguments, exit on failure

    global_debug_enabled = cfg.debug_enabled;             // Set global debug flag

    if (!cfg.kill_daemons && !cfg.hash_enabled && !cfg.payload_enabled) { // Check required options
        log_with_timestamp("Error: At least one of -H or -P must be specified.\n");
        print_help(argv[0]);
        return 1;
    }

    signal(SIGTERM, signal_handler);                      // Register SIGTERM handler
    signal(SIGINT, signal_handler);                       // Register SIGINT handler

    if (cfg.kill_daemons) {                               // Handle kill daemons option
        kill_all_daemons();
        log_with_timestamp("Killed all running daemons\n");
        return 0;
    }

    if (getuid() != 0) {                                  // Check for root privileges
        log_with_timestamp("This program requires root privileges. Please run with sudo.\n");
        return 1;
    }

    if (cfg.daemonize) {                                  // Daemonize if requested
        if (daemon(0, 0) < 0) {                           // Detach from terminal
            log_with_timestamp("Failed to daemonize: %s\n", strerror(errno));
            return 1;
        }
        int logfd = open(LOGFILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644); // Open log file
        if (logfd < 0) {                                  // Check failure
            perror("Failed to open log file for daemon output");
            return 1;
        }
        if (dup2(logfd, STDOUT_FILENO) < 0 || dup2(logfd, STDERR_FILENO) < 0) { // Redirect output
            perror("Failed to redirect stdout/stderr to log file");
            close(logfd);
            return 1;
        }
        close(logfd);                                     // Close log file descriptor
        log_with_timestamp("[INFO] conntrack_logger daemon started, output redirected to %s\n", LOGFILE_PATH);
    }

    int syslog_fd = connect_to_syslog(cfg.syslog_ip, SYSLOG_PORT); // Connect to syslog server
    if (syslog_fd < 0) {                                  // Check connection failure
        log_with_timestamp("[ERROR] Failed to connect to syslog server at %s:%s\n", cfg.syslog_ip, SYSLOG_PORT);
        return 1;
    }

    spsc_queue_t queue;                                   // SPSC queue instance
    spsc_queue_init(&queue, SPSC_QUEUE_CAPACITY);         // Initialize queue (capacity assumed defined)

    atomic_size_t bytes_transferred = 0;                  // Total bytes transferred
    atomic_int overflow_flag = 0;                         // Queue overflow flag

    struct syslog_data sdata = {                          // Initialize syslog thread data
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
    pthread_t syslog_tid;                                 // Syslog thread ID
    if (pthread_create(&syslog_tid, NULL, syslog_thread, &sdata) != 0) { // Create syslog thread
        log_with_timestamp("[ERROR] Failed to create syslog thread\n");
        close(syslog_fd);
        spsc_queue_destroy(&queue);
        return 1;
    }
    pthread_detach(syslog_tid);                           // Detach thread (runs independently)

    struct callback_data cb_data = {                      // Initialize callback data
        .queue = &queue,
        .overflow_flag = &overflow_flag,
        .count_enabled = cfg.count_enabled,
        .hash_enabled = cfg.hash_enabled,
        .payload_enabled = cfg.payload_enabled,
        .event_counter = &event_counter,
        .src_range = cfg.src_range
    };
    struct nfct_handle *cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | // Open conntrack handle
                                        NF_NETLINK_CONNTRACK_UPDATE |
                                        NF_NETLINK_CONNTRACK_DESTROY);
    if (!cth) {                                           // Check failure
        log_with_timestamp("[ERROR] Failed to open conntrack handle: %s\n", strerror(errno));
        close(syslog_fd);
        spsc_queue_destroy(&queue);
        return 1;
    }

    nfct_callback_register(cth, NFCT_T_ALL, event_cb, &cb_data); // Register event callback
    log_with_timestamp("[INFO] Starting to catch conntrack events\n"); // Log start
    if (nfct_catch(cth) < 0) {                            // Catch events (blocks)
        log_with_timestamp("[ERROR] Failed to catch conntrack events: %s\n", strerror(errno));
    }

    nfct_close(cth);                                      // Close conntrack handle
    close(syslog_fd);                                     // Close syslog socket
    spsc_queue_destroy(&queue);                           // Destroy queue
    return 0;                                             // Exit success
}
