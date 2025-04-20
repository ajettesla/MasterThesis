#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>

#define MAX_LINE 1024
#define HASH_SIZE 1024
#define EVENT_WINDOW 100
#define LOG_FILE "conntrack.log"
#define QUEUE_SIZE 1000

typedef struct {
    int event_number;
    long long event_id;
    char timestamp[32];
    char src_ip[16];
    int src_port;
    char dst_ip[16];
    int dst_port;
    char protocol[8];
    char action[16];
    int duration;
    char state[16];
    char flags[16];
} ConntrackEvent;

typedef struct HashNode {
    ConntrackEvent *event;
    struct HashNode *next;
} HashNode;

typedef struct {
    HashNode **buckets;
    int size;
} HashTable;

typedef struct {
    ConntrackEvent *event_a;
    ConntrackEvent *event_b;
} MatchPair;

typedef struct {
    char type[16];
    char message[256];
} LogMessage;

typedef struct {
    MatchPair items[QUEUE_SIZE];
    int front, rear;
    pthread_mutex_t mutex;
} MatchQueue;

typedef struct {
    LogMessage items[QUEUE_SIZE];
    int front, rear;
    pthread_mutex_t mutex;
} LogQueue;

char *log_file_path = NULL;
char *csv_file_path = "matches.csv";
char *machine_a = "MACHINE_A";
char *machine_b = "MACHINE_B";
bool daemon_mode = false;
bool debug_mode = false;
FILE *input_fp;
FILE *csv_file;
FILE *log_file;
HashTable *master_table, *slave_table;
MatchQueue match_queue;
LogQueue log_queue;
int match_count = 0;
int unmatch_count = 0;
int event_count = 0;
time_t start_time;

void init_queue(MatchQueue *q) {
    q->front = q->rear = 0;
    pthread_mutex_init(&q->mutex, NULL);
}

void init_log_queue(LogQueue *q) {
    q->front = q->rear = 0;
    pthread_mutex_init(&q->mutex, NULL);
}

void enqueue_match(MatchQueue *q, MatchPair pair) {
    pthread_mutex_lock(&q->mutex);
    if ((q->rear + 1) % QUEUE_SIZE != q->front) {
        q->items[q->rear] = pair;
        q->rear = (q->rear + 1) % QUEUE_SIZE;
    }
    pthread_mutex_unlock(&q->mutex);
}

bool dequeue_match(MatchQueue *q, MatchPair *pair) {
    pthread_mutex_lock(&q->mutex);
    if (q->front == q->rear) {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }
    *pair = q->items[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&q->mutex);
    return true;
}

void enqueue_log(LogQueue *q, const char *type, const char *message) {
    pthread_mutex_lock(&q->mutex);
    if ((q->rear + 1) % QUEUE_SIZE != q->front) {
        LogMessage msg;
        strncpy(msg.type, type, 16);
        strncpy(msg.message, message, 256);
        q->items[q->rear] = msg;
        q->rear = (q->rear + 1) % QUEUE_SIZE;
    } else {
        fprintf(stderr, "Log queue is full; message dropped: %s\n", message);
    }
    pthread_mutex_unlock(&q->mutex);
}

bool dequeue_log(LogQueue *q, LogMessage *msg) {
    pthread_mutex_lock(&q->mutex);
    if (q->front == q->rear) {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }
    *msg = q->items[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&q->mutex);
    return true;
}

unsigned int hash_function(const char *str, int size) {
    unsigned int hash = 0;
    while (*str) hash = (hash * 31) + (*str++);
    return hash % size;
}

HashTable* create_hash_table(int size) {
    HashTable *ht = malloc(sizeof(HashTable));
    ht->size = size;
    ht->buckets = calloc(size, sizeof(HashNode*));
    return ht;
}

void generate_key(ConntrackEvent *event, char *key) {
    snprintf(key, 64, "%s:%d:%s:%d:%s", event->src_ip, event->src_port,
             event->dst_ip, event->dst_port, event->protocol);
}

void add_event(HashTable *ht, ConntrackEvent *event, const char *key) {
    unsigned int index = hash_function(key, ht->size);
    HashNode *node = malloc(sizeof(HashNode));
    node->event = event;
    node->next = ht->buckets[index];
    ht->buckets[index] = node;
}

ConntrackEvent* find_and_remove_match(HashTable *ht, const char *key, int event_number) {
    unsigned int index = hash_function(key, ht->size);
    HashNode *node = ht->buckets[index], *prev = NULL;
    while (node) {
        char node_key[64];
        generate_key(node->event, node_key);
        if (strcmp(key, node_key) == 0 &&
            abs(node->event->event_number - event_number) <= EVENT_WINDOW) {
            if (prev) prev->next = node->next;
            else ht->buckets[index] = node->next;
            ConntrackEvent *match = node->event;
            free(node);
            return match;
        }
        prev = node;
        node = node->next;
    }
    return NULL;
}

bool parse_event(const char *line, char *machine, ConntrackEvent **event) {
    *event = malloc(sizeof(ConntrackEvent));
    char copy[MAX_LINE];
    strncpy(copy, line, MAX_LINE);
    char *saveptr, *token = strtok_r(copy, " ", &saveptr);
    int count = 0;
    char *event_data = NULL;
    while (token && count < 7) {
        if (count == 2) strncpy(machine, token, 16);
        if (count == 6) event_data = token;
        count++;
        token = strtok_r(NULL, " ", &saveptr);
    }
    if (!event_data) {
        char msg[512];
        snprintf(msg, 512, "Failed to parse line: %s", line);
        enqueue_log(&log_queue, "ERROR", msg);
        free(*event);
        return false;
    }
    token = strtok_r(event_data, ",", &saveptr);
    count = 0;
    while (token && count < 11) {
        switch (count) {
            case 0: (*event)->event_number = atoi(token); break;
            case 1: (*event)->event_id = atoll(token); break;
            case 2: strncpy((*event)->src_ip, token, 16); break;
            case 3: (*event)->src_port = atoi(token); break;
            case 4: strncpy((*event)->dst_ip, token, 16); break;
            case 5: (*event)->dst_port = atoi(token); break;
            case 6: strncpy((*event)->protocol, token, 8); break;
            case 7: strncpy((*event)->action, token, 16); break;
            case 8: (*event)->duration = atoi(token); break;
            case 9: strncpy((*event)->state, token, 16); break;
            case 10: strncpy((*event)->flags, token, 16); break;
        }
        count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    if (count < 11) {
        char msg[512];
        snprintf(msg, 512, "Incomplete event data in line: %s", line);
        enqueue_log(&log_queue, "ERROR", msg);
        free(*event);
        return false;
    }
    token = strtok_r(line, " ", &saveptr);
    if (token) strncpy((*event)->timestamp, token, 32);
    else strncpy((*event)->timestamp, "UNKNOWN", 32);
    return true;
}

void process_event(const char *line) {
    char machine[32];
    ConntrackEvent *event;
    if (!parse_event(line, machine, &event)) {
        return;
    }
    event_count++;
    HashTable *source_table, *target_table;
    char opposite_machine[32];
    if (strcmp(machine, machine_a) == 0) {
        source_table = master_table;
        target_table = slave_table;
        strcpy(opposite_machine, machine_b);
    } else if (strcmp(machine, machine_b) == 0) {
        source_table = slave_table;
        target_table = master_table;
        strcpy(opposite_machine, machine_a);
    } else {
        char msg[256];
        snprintf(msg, 256, "Unknown machine name: %s", machine);
        enqueue_log(&log_queue, "ERROR", msg);
        free(event);
        return;
    }
    char key[64];
    generate_key(event, key);
    ConntrackEvent *match = find_and_remove_match(target_table, key, event->event_number);
    if (match) {
        match_count++;
        MatchPair pair = {event, match};
        enqueue_match(&match_queue, pair);
        if (debug_mode) {
            char msg[512];
            long long id_diff = llabs(event->event_id - match->event_id);
            snprintf(msg, 512, "Matched: %s(%s %s:%d -> %s:%d %s) -> %s(%s %s:%d -> %s:%d %s) -> diff: %lld ns",
                     machine, event->timestamp, event->src_ip, event->src_port, event->dst_ip, event->dst_port, event->protocol,
                     opposite_machine, match->timestamp, match->src_ip, match->src_port, match->dst_ip, match->dst_port, match->protocol,
                     id_diff);
            enqueue_log(&log_queue, "DEBUG", msg);
        }
    } else {
        unmatch_count++;
        add_event(source_table, event, key);
        if (debug_mode) {
            char msg[512];
            snprintf(msg, 512, "No match found for event: %s %s %s:%d -> %s:%d %s",
                     machine, event->timestamp, event->src_ip, event->src_port, event->dst_ip, event->dst_port, event->protocol);
            enqueue_log(&log_queue, "DEBUG", msg);
        }
    }
}

void* reader_thread(void *arg) {
    char line[MAX_LINE];
    enqueue_log(&log_queue, "INFO", "Started processing log file");
    while (1) {
        while (fgets(line, MAX_LINE, input_fp) != NULL) {
            line[strcspn(line, "\n")] = 0;
            process_event(line);
        }
        usleep(100000);
        clearerr(input_fp);
    }
    return NULL;
}

void* writer_thread(void *arg) {
    while (1) {
        MatchPair pair;
        if (dequeue_match(&match_queue, &pair)) {
            fprintf(csv_file, "%d,%s,%s,%d,%s,%s,%s,%d,%s,%d,%s\n",
                    pair.event_a->event_number, pair.event_a->timestamp, machine_a,
                    pair.event_b->event_number, pair.event_b->timestamp, machine_b,
                    pair.event_a->src_ip, pair.event_a->src_port,
                    pair.event_a->dst_ip, pair.event_a->dst_port,
                    pair.event_a->protocol);
            fflush(csv_file);
            free(pair.event_a);
            free(pair.event_b);
        }
        LogMessage msg;
        if (dequeue_log(&log_queue, &msg)) {
            fprintf(log_file, "[%s] %s\n", msg.type, msg.message);
            fflush(log_file);
        }
        usleep(10000);
    }
    return NULL;
}

void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    umask(0);
    setsid();
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}

void print_info(int signum) {
    time_t now = time(NULL);
    double elapsed = difftime(now, start_time);
    double rate = elapsed > 0 ? event_count / elapsed : 0;
    char msg[256];
    snprintf(msg, 256, "Processed: %d, Matches: %d, Unmatched: %d, Rate: %.2f events/sec, Window: %d",
             event_count, match_count, unmatch_count, rate, EVENT_WINDOW);
    enqueue_log(&log_queue, "INFO", msg);
    alarm(60);
}

void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -l <log_file> [-o <csv_file>] [-m <machine_a>] [-s <machine_b>] [-d] [-D] [-h]\n", prog_name);
    fprintf(stderr, "  -l  Log file path (required)\n");
    fprintf(stderr, "  -o  CSV output file path (default: matches.csv)\n");
    fprintf(stderr, "  -m  Master machine name (default: MACHINE_A)\n");
    fprintf(stderr, "  -s  Slave machine name (default: MACHINE_B)\n");
    fprintf(stderr, "  -d  Run as daemon\n");
    fprintf(stderr, "  -D  Enable debug mode\n");
    fprintf(stderr, "  -h  Show this help\n");
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "dDl:o:m:s:h")) != -1) {
        switch (opt) {
            case 'd': daemon_mode = true; break;
            case 'D': debug_mode = true; break;
            case 'l': log_file_path = optarg; break;
            case 'o': csv_file_path = optarg; break;
            case 'm': machine_a = optarg; break;
            case 's': machine_b = optarg; break;
            case 'h': usage(argv[0]); exit(0);
            default: usage(argv[0]); exit(1);
        }
    }
    if (log_file_path == NULL) {
        fprintf(stderr, "Error: -l <log_file> is required\n");
        usage(argv[0]);
        exit(1);
    }

    // Initialize queues
    init_queue(&match_queue);
    init_log_queue(&log_queue);

    // Log configuration
    char msg[256];
    snprintf(msg, 256, "Log file path: %s", log_file_path);
    enqueue_log(&log_queue, "INFO", msg);
    snprintf(msg, 256, "CSV file path: %s", csv_file_path);
    enqueue_log(&log_queue, "INFO", msg);
    snprintf(msg, 256, "Machine A: %s", machine_a);
    enqueue_log(&log_queue, "INFO", msg);
    snprintf(msg, 256, "Machine B: %s", machine_b);
    enqueue_log(&log_queue, "INFO", msg);
    snprintf(msg, 256, "Daemon mode: %s", daemon_mode ? "ON" : "OFF");
    enqueue_log(&log_queue, "INFO", msg);
    snprintf(msg, 256, "Debug mode: %s", debug_mode ? "ON" : "OFF");
    enqueue_log(&log_queue, "INFO", msg);

    input_fp = fopen(log_file_path, "r");
    if (input_fp == NULL) {
        perror("Error opening log file");
        exit(1);
    }
    csv_file = fopen(csv_file_path, "w");
    if (csv_file == NULL) {
        perror("Error opening CSV file");
        exit(1);
    }
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        exit(1);
    }
    if (daemon_mode) {
        daemonize();
    }
    master_table = create_hash_table(HASH_SIZE);
    slave_table = create_hash_table(HASH_SIZE);
    start_time = time(NULL);
    signal(SIGALRM, print_info);
    alarm(60);
    pthread_t reader, writer;
    pthread_create(&reader, NULL, reader_thread, NULL);
    pthread_create(&writer, NULL, writer_thread, NULL);
    pthread_join(reader, NULL);
    pthread_join(writer, NULL);
    fclose(input_fp);
    fclose(csv_file);
    fclose(log_file);
    return 0;
}
