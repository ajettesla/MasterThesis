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
#define SLEEP_USEC        50000
#define RATE_INTERVAL_SEC 1
#define PRUNE_INTERVAL    100
#define MATCH_FIELDS      9   // number of fields to compare

// thread‑safe queue
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
static unsigned long neglected_count = 0; // count of filtered local traffic

// hash entry storing one side’s payload, sequence, and raw query
typedef struct {
    char *key;                    // concatenated MATCH_FIELDS
    unsigned long long ts2;       // payload timestamp
    unsigned long seq;            // sequence number
    char *raw;                    // raw payload string
    UT_hash_handle hh;
} entry_t;

static entry_t *hash_a = NULL, *hash_b = NULL;
static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned long lines_count = 0, match_count = 0;
static unsigned long long win_before = DEFAULT_BASE_WIN, win_after = DEFAULT_BASE_WIN;

// prototypes
void print_usage(const char *p);
void *reader_thr(void *), *processor_thr(void *), *rate_thr(void *);
int is_private_ip(const char *ip);
void enqueue_line(const char *), prune_b(unsigned long long), cleanup(void), do_daemon(void);
char *dequeue_line(void);

void print_usage(const char *p) {
    fprintf(stderr,
      "Usage: %s -l logfile -m MACHINE_A -s MACHINE_B [-D] [-d] [-o output.csv]\n"
      "  -l logfile   : path to log file\n"
      "  -m MACHINE_A : name of machine A\n"
      "  -s MACHINE_B : name of machine B\n"
      "  -D           : debug output on stderr\n"
      "  -d           : run as daemon\n"
      "  -o output.csv: write matches to CSV file\n",
      p);
}

int is_private_ip(const char *ipstr) {
    struct in_addr a;
    if (!inet_aton(ipstr, &a)) return 0;
    unsigned long ip = ntohl(a.s_addr);
    return (ip>>24)==10 || (ip>>20)==0xAC1 || (ip>>16)==0xC0A8;
}

void enqueue_line(const char *line) {
    line_node *n = malloc(sizeof(*n)); if (!n) return;
    n->line = strdup(line); n->next = NULL;
    pthread_mutex_lock(&queue.mutex);
    if (queue.tail) queue.tail->next = n; else queue.head = n;
    queue.tail = n;
    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);
    if (debug) fprintf(stderr, "[DEBUG] enqueued: %s", line);
}

char *dequeue_line(void) {
    pthread_mutex_lock(&queue.mutex);
    while (!queue.head && running) pthread_cond_wait(&queue.cond, &queue.mutex);
    if (!running && !queue.head) { pthread_mutex_unlock(&queue.mutex); return NULL; }
    line_node *n = queue.head; queue.head = n->next; if (!queue.head) queue.tail = NULL;
    pthread_mutex_unlock(&queue.mutex);
    char *ln = n->line; free(n); return ln;
}

void prune_b(unsigned long long pivot) {
    unsigned long long lo = pivot > win_before ? pivot - win_before : 0;
    unsigned long long hi = pivot + win_after;
    pthread_mutex_lock(&hash_mutex);
    entry_t *e, *tmp;
    HASH_ITER(hh, hash_b, e, tmp) {
        if (e->ts2 < lo || e->ts2 > hi) {
            HASH_DEL(hash_b, e);
            free(e->key); free(e->raw); free(e);
        }
    }
    pthread_mutex_unlock(&hash_mutex);
    if (debug) fprintf(stderr, "[DEBUG] pruned B outside [%llu-%llu]\n", lo, hi);
}

void cleanup(void) {
    char *ln;
    while ((ln = dequeue_line()) != NULL) free(ln);
    pthread_mutex_lock(&hash_mutex);
    entry_t *e, *tmp;
    HASH_ITER(hh, hash_a, e, tmp) { HASH_DEL(hash_a, e); free(e->key); free(e->raw); free(e); }
    HASH_ITER(hh, hash_b, e, tmp) { HASH_DEL(hash_b, e); free(e->key); free(e->raw); free(e); }
    pthread_mutex_unlock(&hash_mutex);
    if (output_fp) fclose(output_fp);
}

void *reader_thr(void *_) {
    (void) _;
    FILE *f = NULL; ino_t ino = 0;
    char buf[LINE_MAX];
    while (running) {
        if (!f) {
            f = fopen(logfile_path, "r");
            if (!f) { perror("fopen"); sleep(1); continue; }
            struct stat st;
            if (!stat(logfile_path, &st)) ino = st.st_ino;
            clearerr(f);
        }
        while (fgets(buf, sizeof(buf), f)) enqueue_line(buf);
        if (feof(f)) {
            struct stat st;
            if (!stat(logfile_path, &st) && st.st_ino != ino) { fclose(f); f = NULL; }
            else { clearerr(f); usleep(SLEEP_USEC); }
        }
        if (f && ferror(f)) { perror("fgets"); fclose(f); f = NULL; }
    }
    if (f) fclose(f);
    return NULL;
}

void *processor_thr(void *_) {
    (void) _;
    const char *marker = "conntrack_logger - - -";
    while (running) {
        char *ln = dequeue_line(); if (!ln) break;
        lines_count++;
        char ts_wall[64], host[64], machine[64];
        if (sscanf(ln, "%63s %63s %63s", ts_wall, host, machine) != 3) { free(ln); continue; }
        char *p = strstr(ln, marker); if (!p) { free(ln); continue; }
        p += strlen(marker);
        while (*p == ' ' || *p == '\t') p++;
        char *cpy = strdup(p);
        free(ln);
        if (!cpy) continue;

        // extract and filter
        char *raw = strdup(cpy);
        char *seq_s = strsep(&cpy, ",");
        char *ts2_s = strsep(&cpy, ",");
        char *fields[MATCH_FIELDS]; int cnt = 0;
        while (cnt < MATCH_FIELDS && cpy) fields[cnt++] = strsep(&cpy, ",");
        if (cnt < MATCH_FIELDS) { free(raw); continue; }
        char src[64], dst[64];
        sscanf(fields[0], "%63[^,]", src);
        sscanf(fields[2], "%63[^,]", dst);
        if (is_private_ip(src) && is_private_ip(dst)) { neglected_count++; free(raw); continue; }
        unsigned long seq = strtoul(seq_s, NULL, 10);
        unsigned long long ts2 = strtoull(ts2_s, NULL, 10);

        // build key
        size_t kl = 1;
        for (int i = 0; i < MATCH_FIELDS; i++) kl += strlen(fields[i]) + 1;
        char *key = malloc(kl);
        key[0] = '\0';
        for (int i = 0; i < MATCH_FIELDS; i++) {
            strcat(key, fields[i]);
            if (i < MATCH_FIELDS - 1) strcat(key, "\t");
        }

        int isA = (strcmp(machine, machine_a) == 0);
        pthread_mutex_lock(&hash_mutex);
        entry_t **mine = isA ? &hash_a : &hash_b;
        entry_t **other = isA ? &hash_b : &hash_a;
        entry_t *e;
        HASH_FIND_STR(*mine, key, e);
        if (e) {
            free(e->raw);
            e->ts2 = ts2;
            e->seq = seq;
            e->raw = raw;
            free(key);
        } else {
            e = malloc(sizeof(*e));
            e->key = key;
            e->ts2 = ts2;
            e->seq = seq;
            e->raw = raw;
            HASH_ADD_KEYPTR(hh, *mine, e->key, strlen(e->key), e);
        }
        entry_t *oe;
        HASH_FIND_STR(*other, key, oe);
        if (oe) {
            unsigned long long tsA = isA ? ts2 : oe->ts2;
            unsigned long long tsB = isA ? oe->ts2 : ts2;
            unsigned long sA = isA ? seq : oe->seq;
            unsigned long sB = isA ? oe->seq : seq;
            unsigned long ds = (sA > sB) ? (sA - sB) : (sB - sA);
            unsigned long long dt = (tsA > tsB) ? (tsA - tsB) : (tsB - tsA);
            // CSV output
            if (output_fp) {
                fprintf(output_fp, "%lu,%llu,%lu,%llu,%llu\n", sA, tsA, sB, tsB, dt);
                fflush(output_fp);
            }
            // Info message stdout (normal mode)
            if (!debug) {
                printf("INFO: neglected=%lu rate=%lu win=[%llu-%llu] match seqA=%lu seqB=%lu dt=%lluns ds=%luns\n",
                       neglected_count, lines_count, win_before, win_after, sA, sB, dt, ds);
            }
            // Debug full entries
            if (debug) {
                if (isA) {
                    fprintf(stderr, "[DEBUG] FULL A: %s\n", e->raw);
                    fprintf(stderr, "[DEBUG] FULL B: %s\n", oe->raw);
                } else {
                    fprintf(stderr, "[DEBUG] FULL A: %s\n", oe->raw);
                    fprintf(stderr, "[DEBUG] FULL B: %s\n", e->raw);
                }
            }
            if (++match_count % PRUNE_INTERVAL == 0) prune_b(isA ? oe->ts2 : ts2);
        }
        pthread_mutex_unlock(&hash_mutex);
    }
    return NULL;
}

void *rate_thr(void *_) {
    (void)_;
    while (running) {
        sleep(RATE_INTERVAL_SEC);
        unsigned long c = __sync_lock_test_and_set(&lines_count, 0);
        win_before = DEFAULT_BASE_WIN + c/10;
        win_after = DEFAULT_BASE_WIN + c/10;
    }
    return NULL;
}

void do_daemon(void) {
    pid_t pid = fork(); if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN); signal(SIGHUP, SIG_IGN);
    pid = fork(); if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0); chdir("/"); fclose(stdin); fclose(stdout); fclose(stderr);
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
        print_usage(argv[0]); exit(EXIT_FAILURE);
    }
    if (output_path) {
        output_fp = fopen(output_path, "w");
        if (!output_fp) { perror("fopen out"); exit(EXIT_FAILURE); }
        fprintf(output_fp, "seqA,ts2_A,seqB,ts2_B,delta_time_ns\n");
    }
    if (daemonize_flag) do_daemon();
    setvbuf(stdout, NULL, _IOLBF, 0);

    pthread_t r, p, t;
    pthread_create(&r, NULL, reader_thr, NULL);
    pthread_create(&p, NULL, processor_thr, NULL);
    pthread_create(&t, NULL, rate_thr, NULL);

    pthread_join(r, NULL);
    running = 0;
    pthread_cond_broadcast(&queue.cond);
    pthread_join(p, NULL);
    pthread_join(t, NULL);
    cleanup();
    return 0;
}

