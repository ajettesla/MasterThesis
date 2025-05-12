
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

#define LINE_MAX          2048
#define DEFAULT_BASE_WIN  200
#define SLEEP_USEC        100000  // 100ms sleep
#define RATE_INTERVAL_SEC 1
#define PRUNE_INTERVAL    100
#define MATCH_FIELDS      5   // Matching on protocol, srcip, dstip, srcport, dstport

// Thread-safe queue
typedef struct line_node {
    char *line;
    struct line_node *next;
} line_node;

typedef struct {
    line_node *head, *tail;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
} line_queue;

static line_queue queue = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER };
static volatile int running = 1;
static int debug = 0, daemonize_flag = 0;
static char *logfile_path = NULL, *machine_a = NULL, *machine_b = NULL;
static char *output_path = NULL;
static FILE *output_fp = NULL;

// Tracking counts
typedef struct {
    unsigned long lines_rate;      // Lines processed in last interval
    unsigned long match_pairs;     // Number of matched pairs
    unsigned long total_lines;     // Total lines processed
    unsigned long neglected;       // Filtered private-traffic lines
    unsigned long unmatched_a;     // Unmatched entries in hash_a
    unsigned long unmatched_b;     // Unmatched entries in hash_b
} stats_t;
static stats_t stats = {0, 0, 0, 0, 0, 0};

// Hash entry storing one side’s payload, sequence, and raw query
typedef struct {
    char *key;                    // Concatenated MATCH_FIELDS
    unsigned long long ts2;       // Payload timestamp
    unsigned long seq;            // Sequence number
    char *raw;                    // Raw payload string
    char *protocol;               // Protocol (tcp/udp)
    UT_hash_handle hh;
} entry_t;

static entry_t *hash_a = NULL, *hash_b = NULL;
static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long win_before = DEFAULT_BASE_WIN, win_after = DEFAULT_BASE_WIN;

// Function prototypes
static void print_usage(const char *prog);
static void *reader_thr(void *), *processor_thr(void *), *rate_thr(void *), *progress_thr(void *);
static int is_private_ip(const char *ip);
static void enqueue_line(const char *), prune_b(unsigned long long), cleanup(void), do_daemon(void);
static char *dequeue_line(void);
static void remove_matched_entry(entry_t **hash, char *key);

void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -l logfile -m MACHINE_A -s MACHINE_B [-D] [-d] [-o output.csv]\n"
        "  -l logfile    Path to the log file to tail\n"
        "  -m MACHINE_A  Identifier for machine A in log lines\n"
        "  -s MACHINE_B  Identifier for machine B in log lines\n"
        "  -D            Enable debug output to stderr\n"
        "  -d            Run as a daemon (background)\n"
        "  -o output.csv Write matched entries to CSV file\n",
        prog);
}

int is_private_ip(const char *ipstr) {
    return strcmp(ipstr, "127.0.0.1") == 0;
}

void enqueue_line(const char *line) {
    line_node *n = malloc(sizeof(*n));
    if (!n) return;
    n->line = strdup(line);
    if (!n->line) { free(n); return; }
    n->next = NULL;
    pthread_mutex_lock(&queue.mutex);
    if (queue.tail) queue.tail->next = n;
    else           queue.head = n;
    queue.tail = n;
    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);
    if (debug) fprintf(stderr, "[DEBUG] enqueued: %s", line);
}

char *dequeue_line(void) {
    pthread_mutex_lock(&queue.mutex);
    while (!queue.head && running)
        pthread_cond_wait(&queue.cond, &queue.mutex);
    if (!running && !queue.head) {
        pthread_mutex_unlock(&queue.mutex);
        return NULL;
    }
    line_node *n = queue.head;
    queue.head = n->next;
    if (!queue.head) queue.tail = NULL;
    pthread_mutex_unlock(&queue.mutex);
    char *line = n->line;
    free(n);
    return line;
}

void prune_b(unsigned long long pivot) {
    unsigned long long lo = pivot > win_before ? pivot - win_before : 0;
    unsigned long long hi = pivot + win_after;
    pthread_mutex_lock(&hash_mutex);
    entry_t *e, *tmp;
    HASH_ITER(hh, hash_b, e, tmp) {
        if (e->ts2 < lo || e->ts2 > hi) {
            HASH_DEL(hash_b, e);
            free(e->key);
            free(e->raw);
            free(e->protocol);
            free(e);
            stats.unmatched_b--;
        }
    }
    pthread_mutex_unlock(&hash_mutex);
    if (debug) fprintf(stderr, "[DEBUG] pruned B entries outside [%llu - %llu]\n", lo, hi);
}

void remove_matched_entry(entry_t **hash, char *key) {
    entry_t *e;
    HASH_FIND_STR(*hash, key, e);
    if (e) {
        HASH_DEL(*hash, e);
        free(e->key);
        free(e->raw);
        free(e->protocol);
        free(e);
        if (hash == &hash_a) stats.unmatched_a--;
        else stats.unmatched_b--;
    }
}

void cleanup(void) {
    char *line;
    while ((line = dequeue_line()) != NULL) free(line);
    pthread_mutex_lock(&hash_mutex);
    entry_t *e, *tmp;
    HASH_ITER(hh, hash_a, e, tmp) {
        HASH_DEL(hash_a, e);
        free(e->key);
        free(e->raw);
        free(e->protocol);
        free(e);
    }
    HASH_ITER(hh, hash_b, e, tmp) {
        HASH_DEL(hash_b, e);
        free(e->key);
        free(e->raw);
        free(e->protocol);
        free(e);
    }
    pthread_mutex_unlock(&hash_mutex);
    if (output_fp) fclose(output_fp);
    // Final calculation check
    unsigned long matched_lines = 2 * stats.match_pairs;
    unsigned long total_unmatched = stats.unmatched_a + stats.unmatched_b;
    unsigned long lhs = matched_lines + stats.neglected + total_unmatched;
    if (lhs == stats.total_lines) {
        printf("INFO: Calculation holds: 2*matched=%lu + filtered=%lu + unmatched=%lu = total=%lu (RHS == LHS)\n",
               matched_lines, stats.neglected, total_unmatched, stats.total_lines);
    } else {
        printf("ERROR: Calculation mismatch: 2*matched=%lu + filtered=%lu + unmatched=%lu != total=%lu (RHS != LHS)\n",
               matched_lines, stats.neglected, total_unmatched, stats.total_lines);
    }
}

void *reader_thr(void *_) {
    (void) _;
    FILE *f = NULL;
    ino_t inode = 0;
    char buf[LINE_MAX];
    while (running) {
        if (!f) {
            f = fopen(logfile_path, "r");
            if (!f) { perror("fopen"); sleep(1); continue; }
            struct stat st;
            if (!stat(logfile_path, &st)) inode = st.st_ino;
            clearerr(f);
        }
        while (fgets(buf, sizeof(buf), f)) enqueue_line(buf);
        if (feof(f)) {
            struct stat st;
            if (!stat(logfile_path, &st) && st.st_ino != inode) {
                fclose(f);
                f = NULL;
            } else {
                clearerr(f);
                usleep(SLEEP_USEC);  // 100ms sleep
            }
        }
        if (f && ferror(f)) {
            perror("fgets");
            fclose(f);
            f = NULL;
        }
    }
    if (f) fclose(f);
    return NULL;
}

void *processor_thr(void *_) {
    (void) _;
    const char *marker = "conntrack_logger - - -";
    while (running) {
        char *ln = dequeue_line();
        if (!ln) break;
        stats.lines_rate++;
        stats.total_lines++;

        char ts_wall[64], host[64], machine[64];
        if (sscanf(ln, "%63s %63s %63s", ts_wall, host, machine) != 3) { free(ln); continue; }
        char *p = strstr(ln, marker);
        if (!p) { free(ln); continue; }
        p += strlen(marker);
        while (*p == ' ' || *p == '\t') p++;
        char *cpy = strdup(p);
        free(ln);
        if (!cpy) continue;

        // Extract seq and ts2
        char *raw = strdup(cpy);
        char *seq_s = strsep(&cpy, ",");
        char *ts2_s = strsep(&cpy, ",");
        char *fields[10];  // Assuming up to 10 fields for flexibility
        int cnt = 0;
        while (cnt < 10 && cpy) fields[cnt++] = strsep(&cpy, ",");
        if (cnt < 5) { free(raw); free(cpy); continue; }  // Need at least 5 fields

        // Extract required fields: protocol, srcip, dstip, srcport, dstport
        char *protocol = fields[4];  // Assuming protocol is the 5th field
        char *srcip = fields[0];
        char *dstip = fields[2];
        char *srcport = fields[1];
        char *dstport = fields[3];

       if (is_private_ip(srcip) && is_private_ip(dstip)) {
        stats.neglected++;
        free(raw);
        free(cpy);
        continue;
            }
        unsigned long seq = strtoul(seq_s, NULL, 10);
        unsigned long long ts2 = strtoull(ts2_s, NULL, 10);

        // Build composite key: protocol, srcip, dstip, srcport, dstport
        char *key_fields[] = {protocol, srcip, dstip, srcport, dstport};
        size_t kl = 1;
        for (int i = 0; i < MATCH_FIELDS; i++) kl += strlen(key_fields[i]) + 1;
        char *key = malloc(kl);
        if (!key) { free(raw); free(cpy); continue; }
        key[0] = '\0';
        for (int i = 0; i < MATCH_FIELDS; i++) {
            strcat(key, key_fields[i]);
            if (i < MATCH_FIELDS - 1) strcat(key, "\t");
        }

        int isA = (strcmp(machine, machine_a) == 0);
        pthread_mutex_lock(&hash_mutex);
        entry_t **mine  = isA ? &hash_a : &hash_b;
        entry_t **other = isA ? &hash_b : &hash_a;

        entry_t *e;
        HASH_FIND_STR(*mine, key, e);
        if (e) {
            free(e->raw);
            free(e->protocol);
            e->ts2 = ts2;
            e->seq = seq;
            e->raw = raw;
            e->protocol = strdup(protocol);
            free(key);
        } else {
            e = malloc(sizeof(*e));
            if (!e) { free(key); free(raw); free(cpy); pthread_mutex_unlock(&hash_mutex); continue; }
            e->key = key;
            e->ts2 = ts2;
            e->seq = seq;
            e->raw = raw;
            e->protocol = strdup(protocol);
            HASH_ADD_KEYPTR(hh, *mine, e->key, strlen(e->key), e);
            if (isA) stats.unmatched_a++;
            else stats.unmatched_b++;
        }

        entry_t *oe;
        HASH_FIND_STR(*other, key, oe);
        if (oe) {
            unsigned long long tsA = isA ? ts2 : oe->ts2;
            unsigned long long tsB = isA ? oe->ts2 : ts2;
            unsigned long sA = isA ? seq : oe->seq;
            unsigned long sB = isA ? oe->seq : seq;
            unsigned long ds = sA > sB ? sA - sB : sB - sA;
            unsigned long long dt = tsA > tsB ? tsA - tsB : tsB - tsA;
            char *proto = isA ? e->protocol : oe->protocol;

            // CSV output with protocol
            if (output_fp) {
                fprintf(output_fp, "%lu,%llu,%lu,%llu,%llu,%s\n", sA, tsA, sB, tsB, dt, proto);
                fflush(output_fp);
            }

            // Update stats and remove matched entries
            stats.match_pairs++;
            remove_matched_entry(mine, key);
            remove_matched_entry(other, key);

            if (stats.match_pairs % PRUNE_INTERVAL == 0)
                prune_b(isA ? oe->ts2 : ts2);
        }
        pthread_mutex_unlock(&hash_mutex);
        free(cpy);
    }
    return NULL;
}

void *rate_thr(void *_) {
    (void) _;
    while (running) {
        sleep(RATE_INTERVAL_SEC);
        unsigned long c = __sync_lock_test_and_set(&stats.lines_rate, 0);
        win_before = DEFAULT_BASE_WIN + c/10;
        win_after  = DEFAULT_BASE_WIN + c/10;
    }
    return NULL;
}

void *progress_thr(void *_) {
    (void) _;
    while (running) {
        sleep(5);  // Report progress every 5 seconds
        pthread_mutex_lock(&hash_mutex);
        unsigned long matched_lines = 2 * stats.match_pairs;
        unsigned long total_unmatched = stats.unmatched_a + stats.unmatched_b;
        unsigned long lhs = matched_lines + stats.neglected + total_unmatched;
        printf("PROGRESS: matches=%lu, filtered=%lu, unmatched=%lu, total=%lu (RHS %s LHS)\n",
               stats.match_pairs, stats.neglected, total_unmatched, stats.total_lines,
               (lhs == stats.total_lines) ? "==" : "!=");
        pthread_mutex_unlock(&hash_mutex);
    }
    return NULL;
}

void do_daemon(void) {
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

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "l:m:s:Ddo:")) != -1) {
        switch (opt) {
            case 'l': logfile_path = optarg; break;
            case 'm': machine_a    = optarg; break;
            case 's': machine_b    = optarg; break;
            case 'D': debug        = 1;      break;
            case 'd': daemonize_flag = 1;    break;
            case 'o': output_path  = optarg; break;
            default : print_usage(argv[0]); exit(EXIT_FAILURE);
        }
    }
    if (!logfile_path || !machine_a || !machine_b) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (output_path) {
        output_fp = fopen(output_path, "w");
        if (!output_fp) { perror("fopen output"); exit(EXIT_FAILURE); }
        fprintf(output_fp, "seqA,ts2_A,seqB,ts2_B,delta_time_ns,protocol\n");
    }
    if (daemonize_flag) do_daemon();
    setvbuf(stdout, NULL, _IOLBF, 0);

    pthread_t r_thr, p_thr, t_thr, prog_thr;
    pthread_create(&r_thr, NULL, reader_thr, NULL);
    pthread_create(&p_thr, NULL, processor_thr, NULL);
    pthread_create(&t_thr, NULL, rate_thr, NULL);
    pthread_create(&prog_thr, NULL, progress_thr, NULL);

    pthread_join(r_thr, NULL);
    running = 0;
    pthread_cond_broadcast(&queue.cond);
    pthread_join(p_thr, NULL);
    pthread_join(t_thr, NULL);
    pthread_join(prog_thr, NULL);

    cleanup();
    return 0;
}
