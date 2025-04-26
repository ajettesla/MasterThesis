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
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdbool.h>

static int debug = 0;
static atomic_int connection_counter = 0;
static int total_connections = 0;
static int concurrency = 0;
static double wait_time = 0; // in milliseconds
static char *srv_ip = NULL;
static char *srv_port = NULL;
static char *client_ip_range = NULL;
static char *client_port_range = NULL;
static struct in_addr *source_ips = NULL;
static int num_ips = 0;
static int start_port = 0;
static int num_ports = 0;
static atomic_int next_k = 0;

struct worker_arg {
    int id;
};

bool is_ip_local(const char *ip_str) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return false;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                if (strcmp(host, ip_str) == 0) {
                    freeifaddrs(ifaddr);
                    return true;
                }
            }
        }
    }
    freeifaddrs(ifaddr);
    return false;
}

bool validate_port_range(int start, int end) {
    if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end) {
        return false;
    }
    return true;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s -s <server IP> -p <server port> -n <total connections> -c <concurrency> [-w <wait time>] [-D] [-a <client IP range>] [-r <client port range>] [-h]\n", prog_name);
    printf("Options:\n");
    printf("  -s <server IP>         IP address of the server to send to\n");
    printf("  -p <server port>       Port number of the server\n");
    printf("  -n <total connections> Total number of messages to send\n");
    printf("  -c <concurrency>       Number of worker threads\n");
    printf("  -w <wait time>         Time to wait (in milliseconds) between each message (default: 0)\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -a <client IP range>   IP range for source addresses (e.g., 192.168.1.1-192.168.1.100)\n");
    printf("  -r <client port range> Port range for source ports (e.g., 5000-6000)\n");
    printf("  -h                     Show this help message\n");
    exit(0);
}

void *worker(void *arg) {
    struct worker_arg *wa = (struct worker_arg *)arg;
    int id = wa->id;
    free(wa);

    while (1) {
        int k = atomic_fetch_add(&next_k, 1);
        if (k >= total_connections) break;

        int ip_index = k / num_ports;
        int port_index = k % num_ports;
        struct in_addr source_ip = source_ips[ip_index];
        int source_port = start_port + port_index;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            if (debug) perror("socket");
            continue;
        }

        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr = source_ip;
        local_addr.sin_port = htons(source_port);
        if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            if (debug) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &source_ip, ip_str, INET_ADDRSTRLEN);
                fprintf(stderr, "bind failed for %s:%d: %s\n", ip_str, source_port, strerror(errno));
            }
            close(fd);
            continue;
        }

        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
        struct addrinfo *res;
        if (getaddrinfo(srv_ip, srv_port, &hints, &res) != 0) {
            if (debug) perror("getaddrinfo");
            close(fd);
            continue;
        }

        const char *msg = "hello this is client";
        if (sendto(fd, msg, 19, 0, res->ai_addr, res->ai_addrlen) != 19) {
            if (debug) perror("sendto");
            close(fd);
            freeaddrinfo(res);
            continue;
        }

        if (debug) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source_ip, ip_str, INET_ADDRSTRLEN);
            printf("Worker %d: Sent from %s:%d\n", id, ip_str, source_port);
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            if (debug) perror("setsockopt");
            close(fd);
            freeaddrinfo(res);
            continue;
        }

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

        if (wait_time > 0) {
            usleep((useconds_t)(wait_time * 1000));
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:w:D:a:r:h")) != -1) {
        switch (opt) {
        case 's': srv_ip = strdup(optarg); break;
        case 'p': srv_port = strdup(optarg); break;
        case 'n': total_connections = atoi(optarg); break;
        case 'c': concurrency = atoi(optarg); break;
        case 'w': wait_time = atof(optarg); break;
        case 'D': debug = 1; break;
        case 'a': client_ip_range = strdup(optarg); break;
        case 'r': client_port_range = strdup(optarg); break;
        case 'h': print_usage(argv[0]); break;
        default: print_usage(argv[0]);
        }
    }

    if (!srv_ip || !srv_port || total_connections <= 0 || concurrency <= 0 || !client_ip_range || !client_port_range) {
        fprintf(stderr, "Missing or invalid required arguments\n");
        print_usage(argv[0]);
    }

    char *port_dash = strchr(client_port_range, '-');
    if (!port_dash) {
        fprintf(stderr, "Invalid port range format\n");
        exit(1);
    }
    *port_dash = '\0';
    start_port = atoi(client_port_range);
    int end_port = atoi(port_dash + 1);
    if (!validate_port_range(start_port, end_port)) {
        fprintf(stderr, "Invalid port range %d-%d\n", start_port, end_port);
        exit(1);
    }
    num_ports = end_port - start_port + 1;

    char *ip_dash = strchr(client_ip_range, '-');
    if (!ip_dash) {
        fprintf(stderr, "Invalid IP range format\n");
        exit(1);
    }
    *ip_dash = '\0';
    char *start_ip = client_ip_range;
    char *end_last_octet_str = ip_dash + 1;
    char *last_dot = strrchr(start_ip, '.');
    if (!last_dot) {
        fprintf(stderr, "Invalid IP format\n");
        exit(1);
    }
    *last_dot = '\0';
    char *prefix = start_ip;
    int start_last_octet = atoi(last_dot + 1);
    int end_last_octet = atoi(end_last_octet_str);
    if (start_last_octet < 0 || start_last_octet > 255 ||
        end_last_octet < 0 || end_last_octet > 255 ||
        start_last_octet > end_last_octet) {
        fprintf(stderr, "Invalid IP range\n");
        exit(1);
    }
    num_ips = end_last_octet - start_last_octet + 1;
    source_ips = malloc(num_ips * sizeof(struct in_addr));
    if (!source_ips) {
        perror("malloc");
        exit(1);
    }

    for (int i = 0; i < num_ips; i++) {
        char ip_str[16];
        sprintf(ip_str, "%s.%d", prefix, start_last_octet + i);
        if (!is_ip_local(ip_str)) {
            fprintf(stderr, "Warning: IP %s not available\n", ip_str);
        }
        if (inet_pton(AF_INET, ip_str, &source_ips[i]) != 1) {
            fprintf(stderr, "Invalid IP: %s\n", ip_str);
            exit(1);
        }
    }

    long long total_combinations = (long long)num_ips * num_ports;
    if (total_connections > total_combinations) {
        fprintf(stderr, "Not enough combinations: need %d, have %lld\n", total_connections, total_combinations);
        exit(1);
    }

    printf("Starting %d messages to %s:%s with concurrency %d\n", total_connections, srv_ip, srv_port, concurrency);
    if (wait_time > 0) {
        printf("Wait time between messages: %.3f ms\n", wait_time);
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
            printf("Sent %d messages (%d%%)\n", milestone, (milestone * 100) / total_connections);
            last_milestone = milestone;
        }
        usleep(100000);
    }

    for (int i = 0; i < concurrency; i++)
        pthread_join(threads[i], NULL);

    printf("Completed %d messages.\n", total_connections);

    free(srv_ip);
    free(srv_port);
    free(threads);
    free(source_ips);
    free(client_ip_range);
    free(client_port_range);
    return 0;
}
