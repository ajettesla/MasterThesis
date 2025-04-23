#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <stdatomic.h>
#include <fcntl.h>

static int debug = 0;
static atomic_int connection_counter = 0;
static int total_connections = 0;
static int concurrency = 0;
static char *srv_ip = NULL;
static char *srv_port = NULL;

struct worker_arg {
    int id;
};

// Helper function to read exactly len bytes
ssize_t read_n(int fd, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            if (n == 0) return total; // EOF
            else return -1; // error
        }
        total += n;
    }
    return total;
}

// Helper function to write exactly len bytes
ssize_t write_n(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) return -1;
        total += n;
    }
    return total;
}

void *worker(void *arg) {
    struct worker_arg *wa = (struct worker_arg *)arg;
    int id = wa->id;
    free(wa);

    while (1) {
        int current = atomic_load(&connection_counter);
        if (current >= total_connections) break;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            if (debug) perror("socket");
            continue;
        }

        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res;
        if (getaddrinfo(srv_ip, srv_port, &hints, &res) != 0) {
            if (debug) perror("getaddrinfo");
            close(fd);
            continue;
        }

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            if (debug) perror("connect");
            close(fd);
            freeaddrinfo(res);
            continue;
        }
        freeaddrinfo(res);
        if (debug) printf("Worker %d: Connected\n", id);

        // Send message to server
        const char *msg = "hello this is client";
        if (write_n(fd, msg, 19) < 0) {
            if (debug) perror("write");
            close(fd);
            continue;
        }

        // Receive response from server
        char buf[20];
        ssize_t n = read_n(fd, buf, 19);
        if (n < 0) {
            if (debug) perror("read");
        } else if (n < 19) {
            if (debug) printf("Short read: %zd bytes\n", n);
        } else {
            buf[19] = '\0';
            if (debug) printf("Received: %s\n", buf);
        }

        close(fd);
        atomic_fetch_add(&connection_counter, 1);
    }
    return NULL;
}

void *monitor_conntrack(void *arg) {
    const char *path = "/proc/sys/net/netfilter/nf_conntrack_count";
    long prev = 0, cur = 0;
    char buf[64];
    FILE *f;
    time_t t;
    struct tm tm;

    if (access(path, F_OK) != 0) {
        perror("File does not exist");
        return NULL;
    }

    if ((f = fopen(path, "r")) == NULL) {
        perror("fopen");
    } else {
        if (fgets(buf, sizeof(buf), f))
            prev = atol(buf);
        fclose(f);
    }

    while (atomic_load(&connection_counter) < total_connections) {
        sleep(1);
        if ((f = fopen(path, "r")) == NULL) {
            perror("fopen");
            continue;
        }
        if (fgets(buf, sizeof(buf), f)) {
            cur = atol(buf);
            time(&t);
            localtime_r(&t, &tm);
            char timestr[64];
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
            printf("[%s] nf_conntrack_count=%ld, delta/sec=%+ld\n",
                   timestr, cur, cur - prev);
            fflush(stdout);
            prev = cur;
        }
        fclose(f);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:D")) != -1) {
        switch (opt) {
        case 's': srv_ip = strdup(optarg); break;
        case 'p': srv_port = strdup(optarg); break;
        case 'n': total_connections = atoi(optarg); break;
        case 'c': concurrency = atoi(optarg); break;
        case 'D': debug = 1; break;
        default:
            fprintf(stderr, "Usage: %s -s <server IP> -p <port> -n <total connections> -c <concurrency> [-D]\n", argv[0]);
            exit(1);
        }
    }

    if (!srv_ip || !srv_port || total_connections <= 0 || concurrency <= 0) {
        fprintf(stderr, "Missing or invalid required arguments\n");
        exit(1);
    }

    printf("Starting %d connections to %s:%s with concurrency %d\n",
           total_connections, srv_ip, srv_port, concurrency);

    pthread_t mon_thread;
    if (pthread_create(&mon_thread, NULL, monitor_conntrack, NULL) != 0) {
        perror("pthread_create monitor");
    }

    pthread_t *threads = malloc(concurrency * sizeof(pthread_t));
    if (!threads) { perror("malloc"); exit(1); }

    for (int i = 0; i < concurrency; i++) {
        struct worker_arg *wa = malloc(sizeof(*wa));
        if (!wa) { perror("malloc"); continue; }
        wa->id = i;
        if (pthread_create(&threads[i], NULL, worker, wa) != 0) {
            perror("pthread_create"); free(wa);
        }
    }

    int ten_percent = total_connections / 10;
    if (ten_percent == 0) ten_percent = 1;
    int last_milestone = 0;

    while (1) {
        int current = atomic_load(&connection_counter);
        if (current >= total_connections) break;
        int milestone = (current / ten_percent) * ten_percent;
        if (milestone > last_milestone) {
            printf("Completed %d connections (%d%%)\n",
                   milestone, (milestone * 100) / total_connections);
            last_milestone = milestone;
        }
        usleep(100000);
    }

    for (int i = 0; i < concurrency; i++)
        pthread_join(threads[i], NULL);

    pthread_join(mon_thread, NULL);

    printf("Completed %d connections.\n", total_connections);

    free(srv_ip);
    free(srv_port);
    free(threads);
    return 0;
}
