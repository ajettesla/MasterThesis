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
#include <stdarg.h>

#define INITIAL_OPEN_FDS 1000

static atomic_int connection_counter = 0;
static int total_connections = 0;
static int concurrency = 0;
static double wait_time = 0;
static char *server_ip = NULL;
static char *server_port = NULL;
static char *client_ip_range = NULL;
static char *client_port_range = NULL;
static struct in_addr *source_ips = NULL;
static int num_source_ips = 0;
static int *source_ports = NULL;
static int num_source_ports = 0;
static atomic_int next_task = 0;
static bool kill_flag = false;
static bool reuse_addr = true; // SO_REUSEADDR by default
static bool debug_mode = false;
static volatile sig_atomic_t should_exit = 0;
static char **add_commands = NULL;
static char **del_commands = NULL;
static int num_rules = 0;

struct target_t {
    char *host;
    int port;
};

static struct target_t *targets = NULL;
static int num_targets = 0;
static bool single_server_mode = false;

void print_help(void) {
    printf("Usage:\n");
    printf("  Single-server mode: %s -s <server IP> -p <server port> -n <total connections> [options]\n", "tcp_client");
    printf("\nOptions:\n");
    printf("  -s <server IP>         IP address of the server (single-server mode)\n");
    printf("  -p <server port>       Port number of the server (single-server mode)\n");
    printf("  -n <total connections> Number of connections to make (single-server mode)\n");
    printf("  -c <concurrency>       Number of worker threads\n");
    printf("  -w <wait time>         Wait time (ms) after closing each connection\n");
    printf("  -a <client IP range>   Source IP range (e.g., 192.168.1.1-10)\n");
    printf("  -r <client port range> Source port range (e.g., 5000-5100)\n");
    printf("  -k                     Force RST on close with iptables rule\n");
    printf("  -R                     Enable SO_REUSEADDR (default: enabled)\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -h                     Show this help message\n");
    exit(0);
}

void sigint_handler(int sig) {
    should_exit = 1;
    for (int i = 0; i < num_rules; i++) {
        system(del_commands[i]);
    }
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

void debug_print(const char *fmt, ...) {
    if (debug_mode) {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "DEBUG: ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
    }
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

void parse_ip_range(char *range, struct in_addr **ips, int *num_ips) {
    char *dash = strchr(range, '-');
    if (!dash) {
        fprintf(stderr, "Invalid IP range format\n");
        exit(1);
    }
    *dash = '\0';
    char *start_str = range;
    char *end_str = dash + 1;

    struct in_addr start_ip, end_ip;
    if (inet_pton(AF_INET, start_str, &start_ip) != 1) {
        fprintf(stderr, "Invalid start IP: %s\n", start_str);
        exit(1);
    }

    if (strchr(end_str, '.')) {
        if (inet_pton(AF_INET, end_str, &end_ip) != 1) {
            fprintf(stderr, "Invalid end IP: %s\n", end_str);
            exit(1);
        }
    } else {
        uint32_t ip_num = ntohl(start_ip.s_addr);
        uint32_t prefix = ip_num & 0xFFFFFF00;
        int end_octet = atoi(end_str);
        if (end_octet < 0 || end_octet > 255) {
            fprintf(stderr, "Invalid end octet: %d\n", end_octet);
            exit(1);
        }
        end_ip.s_addr = htonl(prefix | end_octet);
    }

    uint32_t start = ntohl(start_ip.s_addr);
    uint32_t end = ntohl(end_ip.s_addr);
    if (start > end) {
        fprintf(stderr, "Start IP greater than end IP\n");
        exit(1);
    }

    *num_ips = end - start + 1;
    *ips = malloc(sizeof(struct in_addr) * (*num_ips));
    for (uint32_t ip = start; ip <= end; ip++) {
        (*ips)[ip - start].s_addr = htonl(ip);
    }
}

void parse_port_range(char *range, int **ports, int *num_ports) {
    char *dash = strchr(range, '-');
    if (!dash) {
        fprintf(stderr, "Invalid port range format\n");
        exit(1);
    }
    *dash = '\0';
    int start_port = atoi(range);
    int end_port = atoi(dash + 1);
    if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port) {
        fprintf(stderr, "Invalid port range %d-%d\n", start_port, end_port);
        exit(1);
    }
    *num_ports = end_port - start_port + 1;
    *ports = malloc(sizeof(int) * (*num_ports));
    for (int i = 0; i < *num_ports; i++) {
        (*ports)[i] = start_port + i;
    }
}

void *worker(void *arg) {
    int id = *(int*)arg;
    free(arg);

    while (1) {
        if (should_exit) break;
        int task_id = atomic_fetch_add(&next_task, 1);
        if (task_id >= total_connections) break;

        char *target_host;
        int target_port;
        if (single_server_mode) {
            target_host = server_ip;
            target_port = atoi(server_port);
        } else {
            target_host = targets[task_id].host;
            target_port = targets[task_id].port;
        }

        struct in_addr source_ip;
        int source_port = 0;
        if (num_source_ips > 0) {
            int ip_index = task_id % num_source_ips;
            source_ip = source_ips[ip_index];
        } else {
            source_ip.s_addr = 0;
        }
        if (num_source_ports > 0) {
            int port_index = task_id % num_source_ports;
            source_port = source_ports[port_index];
        }

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            if (debug_mode) perror("socket");
            continue;
        }

        if (reuse_addr) {
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        }

        if (num_source_ips > 0 || source_port != 0) {
            struct sockaddr_in local_addr;
            memset(&local_addr, 0, sizeof(local_addr));
            local_addr.sin_family = AF_INET;
            local_addr.sin_addr = source_ip;
            local_addr.sin_port = htons(source_port);
            if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
                if (debug_mode) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &source_ip, ip_str, INET_ADDRSTRLEN);
                    fprintf(stderr, "bind failed for %s:%d: %s\n", ip_str, source_port, strerror(errno));
                }
                close(fd);
                continue;
            }
        }

        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res;
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", target_port);
        if (getaddrinfo(target_host, port_str, &hints, &res) != 0) {
            if (debug_mode) perror("getaddrinfo");
            close(fd);
            continue;
        }

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            if (debug_mode) perror("connect");
            close(fd);
            freeaddrinfo(res);
            continue;
        }
        freeaddrinfo(res);

        if (debug_mode) {
            char source_ip_str[INET_ADDRSTRLEN] = "system";
            if (num_source_ips > 0) {
                inet_ntop(AF_INET, &source_ip, source_ip_str, INET_ADDRSTRLEN);
            }
            printf("Worker %d: Connected from %s:%d to %s:%d\n", id, source_ip_str, source_port, target_host, target_port);
        }

        const char *msg = "hello\n";
        if (write_n(fd, msg, strlen(msg)) < 0) {
            if (debug_mode) perror("write");
            close(fd);
            continue;
        }

        char buf[1024];
        ssize_t n = read_n(fd, buf, 6);
        if (n < 0) {
            if (debug_mode) perror("read");
        } else if (n < 6) {
            if (debug_mode) printf("Short read: %zd bytes\n", n);
        } else {
            buf[6] = '\0';
            if (strcmp(buf, "hello\n") != 0) {
                if (debug_mode) printf("Received unexpected response: '%s'\n", buf);
            } else {
                if (debug_mode) printf("Received expected response\n");
            }
        }

        if (kill_flag) {
            struct linger sl = {1, 0};
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            if (debug_mode) printf("Set SO_LINGER to force RST on close\n");
        }

        close(fd);
        if (debug_mode) printf("Closed connection\n");

        if (wait_time > 0) {
            usleep((useconds_t)(wait_time * 1000));
        }

        int current = atomic_fetch_add(&connection_counter, 1) + 1;
        if (total_connections >= 10) {
            int milestone = total_connections / 10;
            if (current % milestone == 0) {
                printf("Attempted %d connections (%d%%)\n", current, (current * 100) / total_connections);
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:w:a:r:kR:Dh")) != -1) {
        switch (opt) {
            case 's': server_ip = strdup(optarg); break;
            case 'p': server_port = strdup(optarg); break;
            case 'n': total_connections = atoi(optarg); break;
            case 'c': concurrency = atoi(optarg); break;
            case 'w': wait_time = atof(optarg); break;
            case 'a': client_ip_range = strdup(optarg); break;
            case 'r': client_port_range = strdup(optarg); break;
            case 'k': kill_flag = true; break;
            case 'R': reuse_addr = true; break;
            case 'D': debug_mode = true; break;
            case 'h': print_help(); break;
            default:
                fprintf(stderr, "Usage: %s -s <server IP> -p <server port> -n <total connections> [options]\n", argv[0]);
                fprintf(stderr, "Use -h for help\n");
                exit(1);
        }
    }

    if (server_ip && server_port) {
        single_server_mode = true;
        if (optind < argc) {
            fprintf(stderr, "Extra arguments provided with -s and -p\n");
            exit(1);
        }
        if (total_connections <= 0) {
            fprintf(stderr, "Must specify -n > 0 for single server mode\n");
            exit(1);
        }
        num_targets = 1;
    } else {
        int remaining = argc - optind;
        if (remaining % 2 != 0) {
            fprintf(stderr, "Host-port pairs must be in pairs\n");
            exit(1);
        }
        num_targets = remaining / 2;
        if (num_targets == 0) {
            fprintf(stderr, "Must specify either -s and -p or host-port pairs\n");
            exit(1);
        }
        targets = malloc(sizeof(struct target_t) * num_targets);
        for (int i = 0; i < num_targets; i++) {
            targets[i].host = strdup(argv[optind + 2*i]);
            targets[i].port = atoi(argv[optind + 2*i + 1]);
        }
        total_connections = num_targets;
    }

    if (concurrency <= 0) {
        fprintf(stderr, "Must specify -c > 0\n");
        exit(1);
    }

    if (client_ip_range) {
        parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
        for (int i = 0; i < num_source_ips; i++) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source_ips[i], ip_str, INET_ADDRSTRLEN);
            if (!is_ip_local(ip_str)) {
                fprintf(stderr, "Warning: IP address %s is not available on this machine\n", ip_str);
            }
        }
    }

    if (client_port_range) {
        parse_port_range(client_port_range, &source_ports, &num_source_ports);
    }

    signal(SIGINT, sigint_handler);

    if (kill_flag) {
        add_commands = malloc(sizeof(char*) * num_targets);
        del_commands = malloc(sizeof(char*) * num_targets);
        for (int i = 0; i < num_targets; i++) {
            char *host = single_server_mode ? server_ip : targets[i].host;
            int port = single_server_mode ? atoi(server_port) : targets[i].port;
            add_commands[i] = malloc(256);
            del_commands[i] = malloc(256);
            snprintf(add_commands[i], 256, "iptables -A OUTPUT -p tcp -d %s --dport %d --tcp-flags RST RST -j DROP", host, port);
            snprintf(del_commands[i], 256, "iptables -D OUTPUT -p tcp -d %s --dport %d --tcp-flags RST RST -j DROP", host, port);
            system(add_commands[i]);
        }
        num_rules = num_targets;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * concurrency);
    for (int i = 0; i < concurrency; i++) {
        int *id = malloc(sizeof(int));
        *id = i;
        if (pthread_create(&threads[i], NULL, worker, id) != 0) {
            perror("pthread_create");
            free(id);
        }
    }

    for (int i = 0; i < concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    if (kill_flag) {
        for (int i = 0; i < num_rules; i++) {
            system(del_commands[i]);
            free(add_commands[i]);
            free(del_commands[i]);
        }
        free(add_commands);
        free(del_commands);
    }

    printf("Completed %d out of %d connections.\n", atomic_load(&connection_counter), total_connections);

    if (server_ip) free(server_ip);
    if (server_port) free(server_port);
    if (client_ip_range) free(client_ip_range);
    if (client_port_range) free(client_port_range);
    if (source_ips) free(source_ips);
    if (source_ports) free(source_ports);
    if (targets) {
        for (int i = 0; i < num_targets; i++) {
            free(targets[i].host);
        }
        free(targets);
    }
    free(threads);

    return 0;
}
