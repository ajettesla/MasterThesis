#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/inotify.h>
#include <errno.h>
#include <pthread.h>
#include "uthash.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define LINE_SIZE 1024
#define INITIAL_CAPACITY 100

struct Entry {
    long long timestamp;
    int seq;
};

struct KeyGroup {
    char *key;
    char *srcip;
    int srcport;
    char *dstip;
    int dstport;
    char *protocol;
    char *state;
    char *flag;
    struct Entry *entries;
    int count;
    int capacity;
    UT_hash_handle hh;
};

volatile sig_atomic_t sigint_received = 0;
struct KeyGroup *deviceA = NULL, *deviceB = NULL;
struct KeyGroup *unmatchedA = NULL, *unmatchedB = NULL;
FILE *fout = NULL;
FILE *fdebug = NULL;
char *ip_range = NULL;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

// Convert IP string to 32-bit integer
uint32_t ip_to_int(const char *ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "Invalid IP format: %s\n", ip);
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// Check if an IP is within the specified CIDR range
int is_ip_in_range(const char *ip) {
    if (!ip_range) return 1;
    char network_str[16];
    int prefix;
    if (sscanf(ip_range, "%[^/]/%d", network_str, &prefix) != 2) {
        fprintf(stderr, "Invalid CIDR format: %s\n", ip_range);
        return 0;
    }
    uint32_t network_int = ip_to_int(network_str);
    uint32_t ip_int = ip_to_int(ip);
    uint32_t mask = ~((1U << (32 - prefix)) - 1);
    return (ip_int & mask) == (network_int & mask);
}

// Signal handler for Ctrl-C
void sigint_handler(int sig) {
    (void)sig;
    sigint_received = 1;
}

// Sort entries by timestamp
int compare_entries(const void *a, const void *b) {
    const struct Entry *ea = (const struct Entry *)a;
    const struct Entry *eb = (const struct Entry *)b;
    return (ea->timestamp < eb->timestamp) ? -1 : (ea->timestamp > eb->timestamp) ? 1 : 0;
}

// Free a KeyGroup structure
void free_key_group(struct KeyGroup *kg) {
    free(kg->key);
    free(kg->srcip);
    free(kg->dstip);
    free(kg->protocol);
    free(kg->state);
    free(kg->flag);
    free(kg->entries);
    free(kg);
}

// Process a log line and filter by IP range
void process_line(char *line, char *device_a, char *device_b, struct KeyGroup **hash_table, char *device_name, int debug) {
    (void)device_a;
    (void)device_b;
    char timestamp_str[64], hostname[64], device[64], logger[64], payload[512];
    if (sscanf(line, "%63s %63s %63s %63s %*s %*s %*s %511[^\n]", timestamp_str, hostname, device, logger, payload) != 5) {
        if (debug) fprintf(stderr, "Debug: Skipped malformed line: %s\n", line);
        return;
    }
    if (strcmp(device, device_name) != 0) {
        if (debug) fprintf(stderr, "Debug: Skipped line, device '%s' does not match '%s'\n", device, device_name);
        return;
    }

    // Parse payload manually
    char *fields[11];
    int i = 0;
    char *p = payload;
    while (i < 11 && p) {
        fields[i] = p;
        p = strchr(p, ',');
        if (p) *p++ = '\0';
        i++;
    }
    if (i < 11) {
        if (debug) fprintf(stderr, "Debug: Skipped line, incomplete payload (%d fields): %s\n", i, payload);
        return;
    }

    char *srcip = fields[2];
    if (!is_ip_in_range(srcip)) {
        if (debug) fprintf(stderr, "Debug: Skipped line, src IP %s not in range %s\n", srcip, ip_range ? ip_range : "none");
        return;
    }

    int seq = atoi(fields[0]);
    long long timestamp = atoll(fields[1]);
    int srcport = atoi(fields[3]);
    char *dstip = fields[4];
    int dstport = atoi(fields[5]);
    char *protocol = fields[6];
    char *state = fields[7];
    char *flag = fields[9];

    char key[256];
    snprintf(key, sizeof(key), "%s|%d|%s|%d|%s|%s|%s", srcip, srcport, dstip, dstport, protocol, state, flag);

    pthread_mutex_lock(&hash_mutex);
    struct KeyGroup *kg;
    HASH_FIND_STR(*hash_table, key, kg);
    if (!kg) {
        kg = (struct KeyGroup *)malloc(sizeof(struct KeyGroup));
        if (!kg) {
            perror("malloc");
            pthread_mutex_unlock(&hash_mutex);
            exit(EXIT_FAILURE);
        }
        kg->key = strdup(key);
        kg->srcip = strdup(srcip);
        kg->dstip = strdup(dstip);
        kg->srcport = srcport;
        kg->dstport = dstport;
        kg->protocol = strdup(protocol);
        kg->state = strdup(state);
        kg->flag = strdup(flag);
        kg->entries = (struct Entry *)malloc(INITIAL_CAPACITY * sizeof(struct Entry));
        if (!kg->entries) {
            perror("malloc");
            pthread_mutex_unlock(&hash_mutex);
            exit(EXIT_FAILURE);
        }
        kg->count = 0;
        kg->capacity = INITIAL_CAPACITY;
        HASH_ADD_STR(*hash_table, key, kg);
    }

    if (kg->count >= kg->capacity) {
        kg->capacity *= 2;
        struct Entry *new_entries = (struct Entry *)realloc(kg->entries, kg->capacity * sizeof(struct Entry));
        if (!new_entries) {
            perror("realloc");
            pthread_mutex_unlock(&hash_mutex);
            exit(EXIT_FAILURE);
        }
        kg->entries = new_entries;
    }
    kg->entries[kg->count].timestamp = timestamp;
    kg->entries[kg->count].seq = seq;
    kg->count++;
    pthread_mutex_unlock(&hash_mutex);

    if (debug) fprintf(stderr, "Debug: Added event to %s (key: %s, seq: %d, count: %d)\n", device_name, key, seq, kg->count);
}

// Match events between devices and write positive differences
int perform_matching(char *device_a, char *device_b, struct KeyGroup **hashA, struct KeyGroup **hashB, int debug, int debug_extra) {
    pthread_mutex_lock(&hash_mutex);
    int match_count = 0;
    struct KeyGroup *kgA, *tmpA, *kgB;
    HASH_ITER(hh, *hashA, kgA, tmpA) {
        HASH_FIND_STR(*hashB, kgA->key, kgB);
        if (kgB) {
            qsort(kgA->entries, kgA->count, sizeof(struct Entry), compare_entries);
            qsort(kgB->entries, kgB->count, sizeof(struct Entry), compare_entries);
            int pairs = (kgA->count < kgB->count) ? kgA->count : kgB->count;
            for (int i = 0; i < pairs; i++) {
                long long diff = llabs(kgA->entries[i].timestamp - kgB->entries[i].timestamp);
                fprintf(fout, "%lld,%s,%s\n", diff, kgA->protocol, kgA->flag);
                fflush(fout);
                if (debug) {
                    printf("Match: (%s,%d,%s,%d,%s,%s,%d)(%s) -> (%s,%d,%s,%d,%s,%s,%d)(%s), diff=%lld\n",
                           kgA->srcip, kgA->srcport, kgA->dstip, kgA->dstport, kgA->protocol, kgA->flag, kgA->entries[i].seq, device_a,
                           kgB->srcip, kgB->srcport, kgB->dstip, kgB->dstport, kgB->protocol, kgB->flag, kgB->entries[i].seq, device_b, diff);
                }
                if (debug_extra && fdebug) {
                    fprintf(fdebug, "(%s) (%s,%d,%s,%d,%s,%s,%d) -> (%s) (%s,%d,%s,%d,%s,%s,%d)\n",
                            device_a, kgA->srcip, kgA->srcport, kgA->dstip, kgA->dstport, kgA->protocol, kgA->flag, kgA->entries[i].seq,
                            device_b, kgB->srcip, kgB->srcport, kgB->dstip, kgB->dstport, kgB->protocol, kgB->flag, kgB->entries[i].seq);
                    fflush(fdebug);
                }
                match_count++;
            }
            // Move unmatched entries to unmatched hash tables
            if (pairs < kgA->count) {
                memmove(kgA->entries, kgA->entries + pairs, (kgA->count - pairs) * sizeof(struct Entry));
                kgA->count -= pairs;
                HASH_DEL(*hashA, kgA);
                HASH_ADD_STR(unmatchedA, key, kgA);
            } else {
                HASH_DEL(*hashA, kgA);
                free_key_group(kgA);
            }
            if (pairs < kgB->count) {
                memmove(kgB->entries, kgB->entries + pairs, (kgB->count - pairs) * sizeof(struct Entry));
                kgB->count -= pairs;
                HASH_DEL(*hashB, kgB);
                HASH_ADD_STR(unmatchedB, key, kgB);
            } else {
                HASH_DEL(*hashB, kgB);
                free_key_group(kgB);
            }
        } else {
            // Move entire KeyGroup to unmatchedA
            HASH_DEL(*hashA, kgA);
            HASH_ADD_STR(unmatchedA, key, kgA);
        }
    }
    // Handle remaining events in hashB
    HASH_ITER(hh, *hashB, kgB, tmpA) {
        HASH_DEL(*hashB, kgB);
        HASH_ADD_STR(unmatchedB, key, kgB);
    }
    pthread_mutex_unlock(&hash_mutex);
    if (debug && match_count == 0) fprintf(stderr, "Debug: No matches found\n");
    return match_count;
}

// Periodic matching thread function
void *periodic_matching(void *arg) {
    char **devices = (char **)arg;
    char *device_a = devices[0];
    char *device_b = devices[1];
    int debug = *(int *)devices[2];
    int debug_extra = *(int *)devices[3];
    while (!sigint_received) {
        sleep(5);
        pthread_mutex_lock(&hash_mutex);
        int matches = perform_matching(device_a, device_b, &unmatchedA, &unmatchedB, debug, debug_extra);
        pthread_mutex_unlock(&hash_mutex);
        if (debug && matches > 0) fprintf(stderr, "Debug: Periodic thread found %d matches\n", matches);
    }
    return NULL;
}

// Clean up resources
void cleanup() {
    struct KeyGroup *kg, *tmp;
    pthread_mutex_lock(&hash_mutex);
    HASH_ITER(hh, deviceA, kg, tmp) {
        HASH_DEL(deviceA, kg);
        free_key_group(kg);
    }
    HASH_ITER(hh, deviceB, kg, tmp) {
        HASH_DEL(deviceB, kg);
        free_key_group(kg);
    }
    HASH_ITER(hh, unmatchedA, kg, tmp) {
        HASH_DEL(unmatchedA, kg);
        free_key_group(kg);
    }
    HASH_ITER(hh, unmatchedB, kg, tmp) {
        HASH_DEL(unmatchedB, kg);
        free_key_group(kg);
    }
    pthread_mutex_unlock(&hash_mutex);
    if (fout) fclose(fout);
    if (fdebug) fclose(fdebug);
}

int main(int argc, char *argv[]) {
    char *device_a = NULL, *device_b = NULL, *input_file = NULL, *output_file = NULL;
    int debug = 0, debug_extra = 0;
    int opt;
    while ((opt = getopt(argc, argv, "m:s:l:o:Dr:")) != -1) {
        switch (opt) {
            case 'm': device_a = optarg; break;
            case 's': device_b = optarg; break;
            case 'l': input_file = optarg; break;
            case 'o': output_file = optarg; break;
            case 'D':
                if (debug) debug_extra = 1;
                debug = 1;
                break;
            case 'r': ip_range = optarg; break;
            default:
                fprintf(stderr, "Usage: %s -m device_a -s device_b -l input_file -o output_file [-D] [-DD] [-r ip_range]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!device_a || !device_b || !input_file || !output_file) {
        fprintf(stderr, "Missing required options\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin = fopen(input_file, "r");
    if (!fin) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }
    fout = fopen(output_file, "w");
    if (!fout) {
        perror("Failed to open output file");
        fclose(fin);
        exit(EXIT_FAILURE);
    }

    if (debug_extra) {
        char debug_file[256];
        snprintf(debug_file, sizeof(debug_file), "%s.debug", output_file);
        fdebug = fopen(debug_file, "a");
        if (!fdebug) {
            perror("Failed to open debug file");
            fclose(fin);
            fclose(fout);
            exit(EXIT_FAILURE);
        }
        setvbuf(fdebug, NULL, _IOFBF, 1024 * 1024);
    }

    setvbuf(fin, NULL, _IOFBF, 1024 * 1024);
    setvbuf(fout, NULL, _IOFBF, 1024 * 1024);

    signal(SIGINT, sigint_handler);

    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        fclose(fin);
        fclose(fout);
        if (fdebug) fclose(fdebug);
        exit(EXIT_FAILURE);
    }
    int wd = inotify_add_watch(inotify_fd, input_file, IN_MODIFY);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        fclose(fin);
        fclose(fout);
        if (fdebug) fclose(fdebug);
        exit(EXIT_FAILURE);
    }

    // Start periodic matching thread
    char *devices[4] = {device_a, device_b, (char *)&debug, (char *)&debug_extra};
    pthread_t periodic_thread;
    pthread_create(&periodic_thread, NULL, periodic_matching, devices);

    char line[LINE_SIZE];
    int events_processed = 0;
    while (fgets(line, sizeof(line), fin)) {
        process_line(line, device_a, device_b, &deviceA, device_a, debug);
        process_line(line, device_a, device_b, &deviceB, device_b, debug);
        events_processed++;
    }
    if (debug) fprintf(stderr, "Debug: Processed %d lines from initial file\n", events_processed);
    int initial_matches = perform_matching(device_a, device_b, &deviceA, &deviceB, debug, debug_extra);
    printf("%d\n", initial_matches);

    while (!sigint_received) {
        char buffer[BUF_LEN];
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            if (errno == EINTR) continue;
            perror("read");
            break;
        }
        int new_events = 0;
        fseek(fin, 0, SEEK_END);
        while (fgets(line, sizeof(line), fin)) {
            process_line(line, device_a, device_b, &deviceA, device_a, debug);
            process_line(line, device_a, device_b, &deviceB, device_b, debug);
            new_events++;
        }
        if (debug && new_events > 0) fprintf(stderr, "Debug: Processed %d new lines\n", new_events);
        int new_matches = perform_matching(device_a, device_b, &deviceA, &deviceB, debug, debug_extra);
        printf("%d\n", new_matches);
        clearerr(fin);
    }

    // Handle Ctrl+C
    if (sigint_received) {
        printf("Ctrl+C pressed. Waiting for periodic thread to finish...\n");
        pthread_join(periodic_thread, NULL);
        printf("Periodic thread finished. Clearing hash tables...\n");
        sleep(5);
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
    fclose(fin);
    cleanup();

    return 0;
}
