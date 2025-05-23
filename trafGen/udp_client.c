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
static double wait_time = 0;  // Wait time between connections (fractional seconds)
static char *srv_ip = NULL;
static char *srv_port = NULL;

struct worker_arg {
    int id;
};

// Helper function to print usage
void print_usage(const char *prog_name) {
    printf("Usage: %s -s <server IP> -p <port> -n <total connections> -c <concurrency> [-w <wait time>] [-D] [-h]\n", prog_name);
    printf("  -s <server IP>       Server IP address\n");
    printf("  -p <port>            Server port\n");
    printf("  -n <total connections> Total number of connections to make\n");
    printf("  -c <concurrency>     Number of concurrent workers\n");
    printf("  -w <wait time>       Wait time (in seconds) between connections (supports fractional seconds)\n");
    printf("  -D                   Enable debug mode\n");
    printf("  -h                   Show this help message\n");
    exit(0);
}

void *worker(void *arg) {
    struct worker_arg *wa = (struct worker_arg *)arg;
    int id = wa->id;
    free(wa);

    while (1) {
        int current = atomic_load(&connection_counter);
        if (current >= total_connections) break;

        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }; // UDP socket type
        struct addrinfo *res;
        if (getaddrinfo(srv_ip, srv_port, &hints, &res) != 0) {
            if (debug) perror("getaddrinfo");
            continue;
        }

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            if (debug) perror("socket");
            freeaddrinfo(res);
            continue;
        }

        // Set receive timeout for UDP
        struct timeval tv;
        tv.tv_sec = 1;  // Timeout of 1 second
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            if (debug) perror("setsockopt");
            close(fd);
            freeaddrinfo(res);
            continue;
        }

        // Send message to server (UDP)
        const char *msg = "hello this is client";
        if (sendto(fd, msg, 19, 0, res->ai_addr, res->ai_addrlen) != 19) {
            if (debug) perror("sendto");
            close(fd);
            freeaddrinfo(res);
            continue;
        }

        // Receive response from server (UDP)
        char buf[20];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, 19, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (debug) printf("Worker %d: Receive timeout\n", id);
            } else {
                if (debug) perror("recvfrom");
            }
        } else if (n < 19) {
            if (debug) printf("Worker %d: Short receive: %zd bytes\n", id, n);
        } else {
            buf[19] = '\0';
            if (debug) printf("Worker %d: Received: %s\n", id, buf);
        }

        close(fd);
        freeaddrinfo(res);
        atomic_fetch_add(&connection_counter, 1);

        // Add sleep time between connections (supports fractional seconds)
        if (wait_time > 0) {
            usleep((useconds_t)(wait_time * 1000000));  // Convert to microseconds
        }
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
    while ((opt = getopt(argc, argv, "s:p:n:c:w:Dh")) != -1) {  // Added 'h' for help
        switch (opt) {
        case 's': srv_ip = strdup(optarg); break;
        case 'p': srv_port = strdup(optarg); break;
        case 'n': total_connections = atoi(optarg); break;
        case 'c': concurrency = atoi(optarg); break;
        case 'w': wait_time = atof(optarg); break;  // Parse wait time as a double
        case 'D': debug = 1; break;
        case 'h':  // Show help message and exit
            print_usage(argv[0]);
            break;
        default:
            print_usage(argv[0]);
        }
    }

    if (!srv_ip || !srv_port || total_connections <= 0 || concurrency <= 0) {
        fprintf(stderr, "Missing or invalid required arguments\n");
        print_usage(argv[0]);
    }

    printf("Starting %d connections to %s:%s with concurrency %d\n",
           total_connections, srv_ip, srv_port, concurrency);
    if (wait_time > 0) {
        printf("Time wait between connections: %.3f seconds\n", wait_time);
    }

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
