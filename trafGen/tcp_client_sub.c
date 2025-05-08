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
#include <signal.h>

#define INITIAL_OPEN_FDS 1000

static int debug = 0;
static atomic_int connection_counter = 0;
static int total_connections = 0;
static int concurrency = 0;
static double wait_time = 0;
static char *srv_ip = NULL;
static char *srv_port = NULL;
static char *client_ip_range = NULL;
static char *client_port_range = NULL;
static struct in_addr *source_ips = NULL;
static int num_ips = 0;
static int start_port = 0;
static int num_ports = 0;
static atomic_int next_k = 0;
static bool abrupt_close = false;
static bool reuse_addr = false;
static volatile sig_atomic_t should_exit = 0;

struct worker_arg {
    int id;
    int *open_fds;
    int num_open_fds;
    int max_open_fds;
};

void sigint_handler(int sig) {
    printf("Received SIGINT\n");
    should_exit = 1;
}

ssize_t read_n(int fd, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) return n == 0 ? total : -1;
        total += n;
    }
    return total;
}

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
    struct worker_arg *wa = arg;
    int id = wa->id;

    while (1) {
        if (should_exit) break;
        int k = atomic_fetch_add(&next_k, 1);
        if (k >= total_connections) break;

        int ip_index = k / num_ports;
        int port_index = k % num_ports;
        struct in_addr source_ip = source_ips[ip_index];
        int source_port = start_port + port_index;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            if (debug) perror("socket");
            continue;
        }

        if (reuse_addr) {
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
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
        if (debug) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source_ip, ip_str, INET_ADDRSTRLEN);
            printf("Worker %d: Connected with source %s:%d\n", id, ip_str, source_port);
        }

        const char *msg = "hello this is client";
        if (write_n(fd, msg, 19) < 0) {
            if (debug) perror("write");
            close(fd);
            continue;
        }

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

        if (abrupt_close) {
            if (wa->num_open_fds >= wa->max_open_fds) {
                int new_max = wa->max_open_fds * 2;
                int *new_open_fds = realloc(wa->open_fds, sizeof(int) * new_max);
                if (!new_open_fds) {
                    perror("realloc");
                    close(fd);
                } else {
                    wa->open_fds = new_open_fds;
                    wa->max_open_fds = new_max;
                    wa->open_fds[wa->num_open_fds++] = fd;
                }
            } else {
                wa->open_fds[wa->num_open_fds++] = fd;
            }
        } else {
            close(fd);
        }
        atomic_fetch_add(&connection_counter, 1);

        if (wait_time > 0) {
            usleep((useconds_t)(wait_time * 1000));
        }
    }

    for (int i = 0; i < wa->num_open_fds; i++) {
        close(wa->open_fds[i]);
    }
    free(wa->open_fds);
    free(wa);
    return NULL;
}

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

void print_help() {
    printf("Usage: <program_name> -s <server IP> -p <server port> -n <total connections> -c <concurrency> [-w <wait time>] [-D] [-a <client IP range>] [-r <client port range>] [-k] [-R]\n");
    printf("Options:\n");
    printf("  -s <server IP>         IP address of the server to connect to\n");
    printf("  -p <server port>       Port number of the server\n");
    printf("  -n <total connections> Total number of connections to make\n");
    printf("  -c <concurrency>       Number of worker threads\n");
    printf("  -w <wait time>         Time to wait (in milliseconds) between each connection\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -a <client IP range>   IP range for source client addresses\n");
    printf("  -r <client port range> Port range for source client ports\n");
    printf("  -k                     Keep connections open with RST\n");
    printf("  -R                     Enable SO_REUSEADDR for sockets\n");
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:w:D:a:r:kR")) != -1) {
        switch (opt) {
        case 's': srv_ip = strdup(optarg); break;
        case 'p': srv_port = strdup(optarg); break;
        case 'n': total_connections = atoi(optarg); break;
        case 'c': concurrency = atoi(optarg); break;
        case 'w': wait_time = atof(optarg); break;
        case 'D': debug = 1; break;
        case 'a': client_ip_range = strdup(optarg); break;
        case 'r': client_port_range = strdup(optarg); break;
        case 'k': abrupt_close = true; break;
        case 'R': reuse_addr = true; break;
        default:
            print_help();
            exit(1);
        }
    }

    if (!srv_ip || !srv_port || total_connections <= 0 || concurrency <= 0 || !client_ip_range || !client_port_range) {
        fprintf(stderr, "Missing or invalid required arguments\n");
        print_help();
        exit(1);
    }

    signal(SIGINT, sigint_handler);

    char cmd[256];
    if (abrupt_close) {
        snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -p tcp -d %s --dport %s --tcp-flags RST RST -j DROP", srv_ip, srv_port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -p tcp -d %s --dport %s --tcp-flags FIN FIN -j DROP", srv_ip, srv_port);
        system(cmd);
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

    bool all_ips_available = true;
    for (int i = 0; i < num_ips; i++) {
        char ip_str[16];
        sprintf(ip_str, "%s.%d", prefix, start_last_octet + i);
        if (!is_ip_local(ip_str)) {
            fprintf(stderr, "Warning: IP address %s is not available on this machine\n", ip_str);
            all_ips_available = false;
        }
        if (inet_pton(AF_INET, ip_str, &source_ips[i]) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", ip_str);
            exit(1);
        }
    }

    long long total_combinations = (long long)num_ips * num_ports;
    if (total_connections > total_combinations) {
        fprintf(stderr, "Not enough unique combinations: need %d, have %lld\n", total_connections, total_combinations);
        exit(1);
    }

    printf("Starting %d connections to %s:%s with concurrency %d\n",
           total_connections, srv_ip, srv_port, concurrency);
    if (wait_time > 0) {
        printf("Time wait between connections: %.3f milliseconds\n", wait_time);
    }

    pthread_t *threads = malloc(concurrency * sizeof(pthread_t));
    if (!threads) { perror("malloc"); exit(1); }

    for (int i = 0; i < concurrency; i++) {
        struct worker_arg *wa = malloc(sizeof(*wa));
        if (!wa) { perror("malloc"); continue; }
        wa->id = i;
        wa->open_fds = malloc(sizeof(int) * INITIAL_OPEN_FDS);
        if (!wa->open_fds) { perror("malloc"); free(wa); continue; }
        wa->num_open_fds = 0;
        wa->max_open_fds = INITIAL_OPEN_FDS;
        if (pthread_create(&threads[i], NULL, worker, wa) != 0) {
            perror("pthread_create"); free(wa->open_fds); free(wa);
        }
    }

    int ten_percent = total_connections / 10;
    if (ten_percent == 0) ten_percent = 1;
    int last_milestone = 0;

    while (1) {
        if (should_exit) break;
        int current = atomic_load(&connection_counter);
        if (current >= total_connections) break;
        int milestone = (current / ten_percent) * ten_percent;
        if (milestone > last_milestone) {
            printf("Attempted %d connections (%d%%)\n",
                   milestone, (milestone * 100) / total_connections);
            last_milestone = milestone;
        }
        usleep(100000);
    }

    for (int i = 0; i < concurrency; i++)
        pthread_join(threads[i], NULL);

    printf("Completed %d out of %d connections.\n", atomic_load(&connection_counter), total_connections);

    if (abrupt_close) {
        snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -p tcp -d %s --dport %s --tcp-flags RST RST -j DROP 2>/dev/null", srv_ip, srv_port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -p tcp -d %s --dport %s --tcp-flags FIN FIN -j DROP 2>/dev/null", srv_ip, srv_port);
        system(cmd);
    }

    free(srv_ip);
    free(srv_port);
    free(threads);
    free(source_ips);
    free(client_ip_range);
    free(client_port_range);
    return 0;
}
