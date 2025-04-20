#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "uthash.h"

#define LINE_MAX 1024
#define SLEEP_USEC 50000  // 0.05 seconds (50,000 microseconds)

// Hash table structure for storing connection data
typedef struct {
    char *data_b;           // Key: Connection details (data B)
    char *data_a;           // Value: Sequence and connection ID (data A)
    UT_hash_handle hh;      // uthash handle
} hash_entry;

// Function to print usage and help message
void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -l logfile -m MACHINE_A -s MACHINE_B [-D]\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -l logfile     : Path to the log file to monitor\n");
    fprintf(stderr, "  -m MACHINE_A   : Name of the first machine\n");
    fprintf(stderr, "  -s MACHINE_B   : Name of the second machine\n");
    fprintf(stderr, "  -D             : Enable debugging output\n");
}

// Function to process a log line and handle matching
void process_log_line(const char *line, const char *machine_a_name, const char *machine_b_name,
                      hash_entry **hash_table_a, hash_entry **hash_table_b, int debug) {
    // Filter for lines containing "conntrack_logger - - -"
    const char *marker = "conntrack_logger - - -";
    if (strstr(line, marker) == NULL) {
        return;  // Skip irrelevant lines
    }

    // Extract the machine name using sscanf (timestamp, hostname, machine)
    char timestamp[64], hostname[64], machine[64];
    if (sscanf(line, "%63s %63s %63s", timestamp, hostname, machine) != 3) {
        return;
    }

    // Only process if machine matches MACHINE_A or MACHINE_B
    int is_a = (strcmp(machine, machine_a_name) == 0);
    int is_b = (strcmp(machine, machine_b_name) == 0);
    if (!is_a && !is_b) {
        return;
    }

    // Find the data payload after " - - - "
    const char *data_start = strstr(line, " - - - ");
    if (!data_start) return;
    data_start += strlen(" - - - ");

    // Extract data_a and data_b by locating commas
    const char *comma1 = strchr(data_start, ',');
    if (!comma1) return;
    const char *comma2 = strchr(comma1 + 1, ',');
    if (!comma2) return;

    // data_a: from data_start up to comma2
    size_t data_a_len = comma2 - data_start;
    char data_a[data_a_len + 1];
    strncpy(data_a, data_start, data_a_len);
    data_a[data_a_len] = '\0';

    // data_b: everything after the second comma
    const char *data_b = comma2 + 1;

    if (debug) {
        printf("[DEBUG] Line: %s\n", line);
        printf("[DEBUG] Machine: %s, Data A: %s, Data B: %s\n", machine, data_a, data_b);
    }

    // Determine current and other hash tables
    hash_entry **current_ht = is_a ? hash_table_a : hash_table_b;
    hash_entry **other_ht   = is_a ? hash_table_b : hash_table_a;
    const char *curr_name   = is_a ? machine_a_name : machine_b_name;
    const char *other_name  = is_a ? machine_b_name : machine_a_name;

    // Insert or update in current hash table
    hash_entry *entry = NULL;
    HASH_FIND_STR(*current_ht, data_b, entry);
    if (entry) {
        free(entry->data_a);
        entry->data_a = strdup(data_a);
    } else {
        entry = malloc(sizeof(hash_entry));
        entry->data_b = strdup(data_b);
        entry->data_a = strdup(data_a);
        HASH_ADD_STR(*current_ht, data_b, entry);
    }

    // Check for a match in the other table
    hash_entry *other_entry = NULL;
    HASH_FIND_STR(*other_ht, data_b, other_entry);
    if (other_entry) {
        if (debug) {
            printf("[DEBUG] Match found for data_b: %s\n", data_b);
        }
        // Print in the format: (A (dataA)) -> B (dataB)
        if (is_a) {
            printf("(%s (%s)) -> %s (%s)\n", curr_name, entry->data_a, other_name, other_entry->data_a);
        } else {
            printf("(%s (%s)) -> %s (%s)\n", other_name, other_entry->data_a, curr_name, entry->data_a);
        }
    }
}

int main(int argc, char *argv[]) {
    char *logfile_path = NULL;
    char *machine_a_name = NULL;
    char *machine_b_name = NULL;
    int debug = 0;
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "l:m:s:D")) != -1) {
        switch (opt) {
            case 'l': logfile_path = optarg; break;
            case 'm': machine_a_name = optarg; break;
            case 's': machine_b_name = optarg; break;
            case 'D': debug = 1; break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!logfile_path || !machine_a_name || !machine_b_name) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    hash_entry *hash_table_a = NULL;
    hash_entry *hash_table_b = NULL;

    // Open the logfile, with retry and rotation handling
    FILE *file = NULL;
    ino_t current_inode = 0;
    while (!file) {
        file = fopen(logfile_path, "r");
        if (!file) {
            if (debug) fprintf(stderr, "[DEBUG] fopen failed: %s\n", strerror(errno));
            sleep(1);
        } else {
            struct stat sb;
            if (stat(logfile_path, &sb) == 0) {
                current_inode = sb.st_ino;
            } else {
                if (debug) fprintf(stderr, "[DEBUG] stat failed: %s\n", strerror(errno));
                fclose(file);
                file = NULL;
                sleep(1);
            }
        }
    }

    char line[LINE_MAX];
    while (1) {
        if (fgets(line, sizeof(line), file)) {
            line[strcspn(line, "\n")] = '\0';
            process_log_line(line, machine_a_name, machine_b_name,
                             &hash_table_a, &hash_table_b, debug);
        } else if (feof(file)) {
            struct stat sb;
            if (stat(logfile_path, &sb) == 0 && sb.st_ino != current_inode) {
                if (debug) printf("[DEBUG] Log rotated, reopening...\n");
                fclose(file);
                file = NULL;
                while (!file) {
                    file = fopen(logfile_path, "r");
                    if (!file) { sleep(1); }
                    else { current_inode = sb.st_ino; }
                }
            } else {
                usleep(SLEEP_USEC);
            }
        } else if (ferror(file)) {
            if (debug) fprintf(stderr, "[DEBUG] fgets error: %s\n", strerror(errno));
            fclose(file);
            file = NULL;
            while (!file) {
                file = fopen(logfile_path, "r");
                if (!file) { sleep(1); }
                else {
                    struct stat sb;
                    if (stat(logfile_path, &sb) == 0) current_inode = sb.st_ino;
                }
            }
        }
    }

    // Unreachable
    fclose(file);
    return 0;
}

