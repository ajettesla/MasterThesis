#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "uthash.h"

#define LINE_MAX 2048
#define DEFAULT_BASE_WINDOW 200
#define SLEEP_USEC 50000
#define RATE_INTERVAL_SEC 1

// Thread-safe queue for log lines
typedef struct line_node {
    char *line;
    struct line_node *next;
} line_node;

typedef struct {
    line_node *head, *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} line_queue;

static line_queue queue = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER };
static volatile int running = 1;
static int debug = 0;
static int daemonize_flag = 0;

// Global log file path and machine names
static char *logfile_path = NULL;
static char *machine_a_name = NULL;
static char *machine_b_name = NULL;

// Hash entry structure
typedef struct {
    char *data_b;
    char *data_a;
    UT_hash_handle hh;
} hash_entry;

static hash_entry *hash_a = NULL;
static hash_entry *hash_b = NULL;

// Dynamic window sizes
static unsigned long long window_before = DEFAULT_BASE_WINDOW;
static unsigned long long window_after  = DEFAULT_BASE_WINDOW;

// Rate counter
static unsigned long lines_count = 0;

// Function prototypes
void print_usage(const char *prog_name);
void *reader_thread(void *arg);
void *processor_thread(void *arg);
void *rate_adjuster_thread(void *arg);
int  is_private_ip(const char *ip_str);
void enqueue_line(const char *line);
char *dequeue_line(void);
void prune_table_b(unsigned long long pivot);
void do_daemonize(void);

// Print usage
void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -l logfile -m MACHINE_A -s MACHINE_B [-D] [-d]\n", prog_name);
    fprintf(stderr, "  -l logfile   : Path to the log file to monitor\n");
    fprintf(stderr, "  -m MACHINE_A : Name of the first machine\n");
    fprintf(stderr, "  -s MACHINE_B : Name of the second machine\n");
    fprintf(stderr, "  -D           : Enable debugging output\n");
    fprintf(stderr, "  -d           : Run as daemon\n");
}

// Check if IP is private
int is_private_ip(const char *ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) return 0;
    unsigned long ip = ntohl(addr.s_addr);
    if ((ip >> 24) == 10) return 1;
    if ((ip >> 20) == 0xAC1) return 1;   // 172.16.0.0/12
    if ((ip >> 16) == 0xC0A8) return 1; // 192.168.0.0/16
    return 0;
}

// Enqueue a line into the queue
void enqueue_line(const char *line) {
    line_node *node = malloc(sizeof(*node));
    node->line = strdup(line);
    node->next = NULL;
    pthread_mutex_lock(&queue.mutex);
    if (queue.tail) queue.tail->next = node;
    else queue.head = node;
    queue.tail = node;
    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);
}

// Dequeue a line from the queue
char *dequeue_line(void) {
    pthread_mutex_lock(&queue.mutex);
    while (!queue.head && running) {
        pthread_cond_wait(&queue.cond, &queue.mutex);
    }
    if (!running) {
        pthread_mutex_unlock(&queue.mutex);
        return NULL;
    }
    line_node *node = queue.head;
    queue.head = node->next;
    if (!queue.head) queue.tail = NULL;
    pthread_mutex_unlock(&queue.mutex);
    char *line = node->line;
    free(node);
    return line;
}

// Prune hash_b based on sliding window around pivot
void prune_table_b(unsigned long long pivot) {
    hash_entry *cur, *tmp;
    unsigned long long seq;
    int pruned = 0;
    unsigned long long low  = (pivot > window_before) ? pivot - window_before : 0;
    unsigned long long high = pivot + window_after;
    HASH_ITER(hh, hash_b, cur, tmp) {
        if (sscanf(cur->data_a, "%llu", &seq) != 1) continue;
        if (seq < low || seq > high) {
            HASH_DEL(hash_b, cur);
            free(cur->data_b);
            free(cur->data_a);
            free(cur);
            pruned++;
        }
    }
    if (debug) fprintf(stderr, "[DEBUG] Pruned %d entries outside [%llu-%llu]\n", pruned, low, high);
}

// Reader thread: tails the log file and enqueues lines
void *reader_thread(void *arg) {
    FILE *f = NULL;
    ino_t curr_ino = 0;
    char buf[LINE_MAX];
    while (running) {
        if (!f) {
            f = fopen(logfile_path, "r");
            if (!f) { sleep(1); continue; }
            struct stat sb;
            if (stat(logfile_path, &sb) == 0) curr_ino = sb.st_ino;
            clearerr(f);
        }
        while (fgets(buf, sizeof(buf), f)) {
            enqueue_line(buf);
        }
        if (feof(f)) {
            struct stat sb;
            if (stat(logfile_path, &sb) == 0 && sb.st_ino != curr_ino) {
                fclose(f);
                f = NULL;
            } else {
                clearerr(f);
                usleep(SLEEP_USEC);
            }
        }
        if (ferror(f)) {
            fclose(f);
            f = NULL;
        }
    }
    return NULL;
}

// Processor thread: processes lines, matches entries, prints output
void *processor_thread(void *arg) {
    const char *marker = "conntrack_logger - - -";
    while (running) {
        char *line = dequeue_line();
        if (!line) break;
        lines_count++;
        if (!strstr(line, marker)) {
            free(line);
            continue;
        }
        char ts[64], host[64], machine[64];
        if (sscanf(line, "%63s %63s %63s", ts, host, machine) != 3) {
            free(line);
            continue;
        }
        int is_a = (strcmp(machine, machine_a_name) == 0);
        int is_b = (strcmp(machine, machine_b_name) == 0);
        if (!is_a && !is_b) {
            free(line);
            continue;
        }
        // Extract data payload
        char *payload = strstr(line, marker) + strlen(marker);
        while (*payload == ' ') payload++;
        char *c1 = strchr(payload, ',');
        if (!c1) {
            free(line);
            continue;
        }
        char *c2 = strchr(c1 + 1, ',');
        if (!c2) {
            free(line);
            continue;
        }
        *c2 = '\0';
        char *data_a = payload;
        char *data_b = c2 + 1;
        // Filter local traffic by IPs
        char temp[LINE_MAX];
        strncpy(temp, data_b, LINE_MAX - 1);
        temp[LINE_MAX - 1] = '\0'; // Ensure null-termination
        char *src = strtok(temp, ",");
        if (!src) {
            free(line);
            continue;
        }
        char *port = strtok(NULL, ",");
        if (!port) {
            free(line);
            continue;
        }
        char *dst = strtok(NULL, ",");
        if (!dst) {
            free(line);
            continue;
        }
        if (is_private_ip(src) && is_private_ip(dst)) {
            free(line);
            continue;
        }
        // Update hash tables
        hash_entry **curr = is_a ? &hash_a : &hash_b;
        hash_entry **other = is_a ? &hash_b : &hash_a;
        hash_entry *e;
        HASH_FIND_STR(*curr, data_b, e);
        if (e) {
            free(e->data_a);
            e->data_a = strdup(data_a);
        } else {
            e = malloc(sizeof(*e));
            e->data_b = strdup(data_b);
            e->data_a = strdup(data_a);
            HASH_ADD_STR(*curr, data_b, e);
        }
        // Check for match
        hash_entry *oe;
        HASH_FIND_STR(*other, data_b, oe);
        if (oe) {
            unsigned long long pivot = 0;
            sscanf(is_a ? oe->data_a : e->data_a, "%llu", &pivot);
            printf("(%s (%s)) -> %s (%s)",
                   is_a ? machine_a_name : machine_b_name,
                   is_a ? e->data_a : oe->data_a,
                   is_a ? machine_b_name : machine_a_name,
                   is_a ? oe->data_a : e->data_a);
            prune_table_b(pivot);
            printf(" [window=[%llu-%llu]]\n", window_before, window_after);
            fflush(stdout);
        }
        free(line); // Free line after all processing
    }
    return NULL;
}

// Rate adjuster thread: updates window sizes based on line rate
void *rate_adjuster_thread(void *arg) {
    while (running) {
        sleep(RATE_INTERVAL_SEC);
        unsigned long count = __sync_lock_test_and_set(&lines_count, 0);
        window_before = DEFAULT_BASE_WINDOW + count / 10;
        window_after  = DEFAULT_BASE_WINDOW + count / 10;
        if (debug)
            fprintf(stderr, "[DEBUG] Rate %lu lines/sec, window=[%llu-%llu]\n",
                    count, window_before, window_after);
    }
    return NULL;
}

// Daemonize process
void do_daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "l:m:s:Dd")) != -1) {
        switch (opt) {
            case 'l': logfile_path    = optarg; break;
            case 'm': machine_a_name  = optarg; break;
            case 's': machine_b_name  = optarg; break;
            case 'D': debug = 1;               break;
            case 'd': daemonize_flag = 1;      break;
            default:  print_usage(argv[0]);    exit(EXIT_FAILURE);
        }
    }
    if (!logfile_path || !machine_a_name || !machine_b_name) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (daemonize_flag) {
        do_daemonize();
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    pthread_t reader_thr, proc_thr, rate_thr;
    pthread_create(&reader_thr, NULL, reader_thread, NULL);
    pthread_create(&proc_thr,   NULL, processor_thread, NULL);
    pthread_create(&rate_thr,   NULL, rate_adjuster_thread, NULL);

    pthread_join(reader_thr, NULL);
    running = 0;
    pthread_cond_broadcast(&queue.cond);
    pthread_join(proc_thr, NULL);
    pthread_join(rate_thr, NULL);

    return 0;
}
