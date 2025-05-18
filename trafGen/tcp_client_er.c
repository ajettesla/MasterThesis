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

// Function prototype to fix implicit declaration
void debug_print(const char *fmt, ...);

// Global variables
static atomic_int connection_counter = 0; // Tracks completed connections
static int total_connections = 0;         // Total connections to make
static int concurrency = 0;               // Number of worker threads
static double wait_time = 0;              // Wait time after closing (ms)
static char *server_ip = NULL;            // Server IP (single-server mode)
static char *server_port = NULL;          // Server port (single-server mode)
static char *client_ip_range = NULL;      // Source IP range
static char *client_port_range = NULL;    // Source port range
static struct in_addr *source_ips = NULL; // Parsed source IPs
static int num_source_ips = 0;            // Number of source IPs
static int *source_ports = NULL;          // Parsed source ports
static int num_source_ports = 0;          // Number of source ports
static atomic_int next_task = 0;          // Next task index for threads
static bool kill_flag = false;            // Force RST with iptables
static bool debug_mode = false;           // Enable debug output
static volatile sig_atomic_t should_exit = 0; // Signal flag for exit
static char *add_command = NULL;          // iptables add command
static char *del_command = NULL;          // iptables delete command

// Structure for target servers
struct target_t {
    char *host;
    int port;
};

static struct target_t *targets = NULL;   // Array of target servers
static int num_targets = 0;               // Number of targets
static bool single_server_mode = false;   // Single vs. multiple server mode

// Print usage instructions
void print_help(void) {
    printf("Usage:\n");
    printf("  %s -s <server IP> -p <server port> -n <total connections> [options]\n", "tcp_client");
    printf("\nOptions:\n");
    printf("  -s <server IP>         IP address of the server\n");
    printf("  -p <server port>       Port number of the server\n");
    printf("  -n <total connections> Number of connections to make\n");
    printf("  -c <concurrency>       Number of worker threads\n");
    printf("  -w <wait time>         Wait time (ms) after closing each connection\n");
    printf("  -a <client IP range>   Source IP range (e.g., 192.168.1.1-10)\n");
    printf("  -r <client port range> Source port range (e.g., 5000-5100)\n");
    printf("  -k                     Force RST on close with iptables rule\n");
    printf("  -D                     Enable debug mode\n");
    printf("  -h                     Show this help message\n");
    printf("\nNote: Additional host-port pairs can be specified as arguments.\n");
    exit(0);
}

// Handle SIGINT (Ctrl+C) to clean up iptables rules
void sigint_handler(int sig) {
    should_exit = 1;
    if (kill_flag) {
        system(del_command);
        debug_print("Removed general iptables rule on Ctrl+C");
    }
}

// Read exactly n bytes from a file descriptor with timeout
ssize_t read_n(int fd, char *buf, size_t len) {
    size_t total = 0;
    struct timeval timeout;
    timeout.tv_sec = 1; // 1-second timeout
    timeout.tv_usec = 0;

    while (total < len) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);

        int ret = select(fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ret < 0) {
            return -1; // Error
        } else if (ret == 0) {
            // Timeout occurred
            if (should_exit) {
                return -2; // Custom error code for should_exit
            }
            continue; // Keep waiting
        } else {
            // Socket is readable
            ssize_t n = read(fd, buf + total, len - total);
            if (n <= 0) {
                return n == 0 ? total : -1;
            }
            total += n;
        }
    }
    return total;
}

// Write exactly n bytes to a file descriptor with timeout
ssize_t write_n(int fd, const char *buf, size_t len) {
    size_t total = 0;
    struct timeval timeout;
    timeout.tv_sec = 1; // 1-second timeout
    timeout.tv_usec = 0;

    while (total < len) {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd, &write_fds);

        int ret = select(fd + 1, NULL, &write_fds, NULL, &timeout);
        if (ret < 0) {
            return -1; // Error
        } else if (ret == 0) {
            // Timeout occurred
            if (should_exit) {
                return -2; // Custom error code for should_exit
            }
            continue; // Keep waiting
        } else {
            // Socket is writable
            ssize_t n = write(fd, buf + total, len - total);
            if (n < 0) {
                return -1;
            }
            total += n;
        }
    }
    return total;
}

// Print debug messages if debug mode is enabled
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

// Check if an IP address is available on the local machine
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

// Parse an IP range (e.g., "192.168.1.1-10") into an array of in_addr
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

// Parse a port range (e.g., "5000-5100") into an array of integers
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

// Worker thread function to handle connections
void *worker(void *arg) {
    int id = *(int*)arg;
    free(arg);

    while (1) {
        if (should_exit) break;
        int task_id = atomic_fetch_add(&next_task, 1);
        if (task_id >= total_connections) break;

        // Determine target host and port
        char *target_host;
        int target_port;
        if (single_server_mode) {
            target_host = server_ip;
            target_port = atoi(server_port);
        } else {
            target_host = targets[task_id % num_targets].host;
            target_port = targets[task_id % num_targets].port;
        }

        // Select source IP and port
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

        // Create socket
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            if (debug_mode) perror("socket");
            continue;
        }

        // Set socket to non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            if (debug_mode) perror("fcntl F_GETFL");
            close(fd);
            continue;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            if (debug_mode) perror("fcntl F_SETFL");
            close(fd);
            continue;
        }

        // Enable SO_REUSEADDR
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        debug_print("Worker %d: Enabled SO_REUSEADDR for task %d", id, task_id);

        // Bind to source IP/port if specified
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
            debug_print("Worker %d: Bound to %s:%d for task %d", id, inet_ntoa(source_ip), source_port, task_id);
        }

        // Resolve target address
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res;
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", target_port);
        if (getaddrinfo(target_host, port_str, &hints, &res) != 0) {
            if (debug_mode) perror("getaddrinfo");
            close(fd);
            continue;
        }

        debug_print("Worker %d: Connecting to %s:%d for task %d", id, target_host, target_port, task_id);

        // Non-blocking connect
        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                if (debug_mode) perror("connect");
                close(fd);
                freeaddrinfo(res);
                continue;
            }
        }

        // Wait for connect to complete
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd, &write_fds);
        int ret = select(fd + 1, NULL, &write_fds, NULL, &timeout);
        if (ret < 0) {
            if (debug_mode) perror("select");
            close(fd);
            freeaddrinfo(res);
            continue;
        } else if (ret == 0) {
            // Timeout
            if (should_exit) {
                close(fd);
                freeaddrinfo(res);
                continue;
            }
            // Optionally retry or fail
            debug_print("Worker %d: Connect timeout to %s:%d", id, target_host, target_port);
            close(fd);
            freeaddrinfo(res);
            continue;
        } else {
            // Check if connect succeeded
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                if (debug_mode) perror("getsockopt");
                close(fd);
                freeaddrinfo(res);
                continue;
            }
            if (error != 0) {
                if (debug_mode) fprintf(stderr, "connect failed: %s\n", strerror(error));
                close(fd);
                freeaddrinfo(res);
                continue;
            }
        }
        freeaddrinfo(res);

        debug_print("Worker %d: Connected to %s:%d for task %d", id, target_host, target_port, task_id);

        // Send message
        const char *msg = "hello\n";
        if (write_n(fd, msg, strlen(msg)) < 0) {
            if (write_n(fd, msg, strlen(msg)) == -2 && should_exit) {
                close(fd);
                break;
            }
            if (debug_mode) perror("write");
            close(fd);
            continue;
        }
        debug_print("Worker %d: Sent 'hello' to %s:%d", id, target_host, target_port);

        // Receive response
        char buf[1024];
        ssize_t n = read_n(fd, buf, 6);
        if (n < 0) {
            if (n == -2 && should_exit) {
                close(fd);
                break;
            }
            if (debug_mode) perror("read");
        } else if (n < 6) {
            debug_print("Worker %d: Short read from %s:%d, got %zd bytes", id, target_host, target_port, n);
        } else {
            buf[6] = '\0';
            debug_print("Worker %d: Received '%s' from %s:%d", id, buf, target_host, target_port);
        }

        // Force RST if enabled
        if (kill_flag) {
            struct linger sl = {1, 0};
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            debug_print("Worker %d: Set SO_LINGER to force RST for task %d", id, task_id);
        }

        // Close connection
        close(fd);
        debug_print("Worker %d: Closed connection to %s:%d", id, target_host, target_port);

        // Wait if specified
        if (wait_time > 0) {
            usleep((useconds_t)(wait_time * 1000));
            debug_print("Worker %d: Waited %.2f ms after closing", id, wait_time);
        }

        // Update and report progress
        int current = atomic_fetch_add(&connection_counter, 1) + 1;
        if (total_connections >= 10 && current % (total_connections / 10) == 0) {
            printf("Progress: %d/%d connections (%d%%)\n", current, total_connections, (current * 100) / total_connections);
        }
    }
    debug_print("Worker %d: Exiting", id);
    return NULL;
}

// Main function
int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:n:c:w:a:r:kDh")) != -1) {
        switch (opt) {
            case 's': server_ip = strdup(optarg); break;
            case 'p': server_port = strdup(optarg); break;
            case 'n': total_connections = atoi(optarg); break;
            case 'c': concurrency = atoi(optarg); break;
            case 'w': wait_time = atof(optarg); break;
            case 'a': client_ip_range = strdup(optarg); break;
            case 'r': client_port_range = strdup(optarg); break;
            case 'k': kill_flag = true; break;
            case 'D': debug_mode = true; break;
            case 'h': print_help(); break;
            default:
                fprintf(stderr, "Usage: %s -s <server IP> -p <server port> -n <total connections> [options]\n", argv[0]);
                exit(1);
        }
    }

    // Determine mode and parse targets
    if (server_ip && server_port) {
        single_server_mode = true;
        if (total_connections <= 0) {
            fprintf(stderr, "Must specify -n > 0 with -s and -p\n");
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
        if (num_targets > 0) {
            targets = malloc(sizeof(struct target_t) * num_targets);
            for (int i = 0; i < num_targets; i++) {
                targets[i].host = strdup(argv[optind + 2*i]);
                targets[i].port = atoi(argv[optind + 2*i + 1]);
            }
            total_connections = num_targets;
        } else {
            fprintf(stderr, "Must specify -s and -p or host-port pairs\n");
            exit(1);
        }
    }

    // Validate concurrency
    if (concurrency <= 0) {
        fprintf(stderr, "Must specify -c > 0\n");
        exit(1);
    }

    // Parse source IP range
    if (client_ip_range) {
        parse_ip_range(client_ip_range, &source_ips, &num_source_ips);
        for (int i = 0; i < num_source_ips; i++) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source_ips[i], ip_str, INET_ADDRSTRLEN);
            if (!is_ip_local(ip_str)) {
                fprintf(stderr, "Warning: IP %s not local\n", ip_str);
            }
        }
    }

    // Parse source port range
    if (client_port_range) {
        parse_port_range(client_port_range, &source_ports, &num_source_ports);
    }

    // Set up signal handler
    signal(SIGINT, sigint_handler);

    // Set up iptables rule if forcing RST
    if (kill_flag) {
        add_command = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        del_command = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
        if (system(add_command) != 0) {
            fprintf(stderr, "Failed to add iptables rule\n");
            exit(1);
        }
        debug_print("Added general iptables rule");
    }

    // Create worker threads
    pthread_t *threads = malloc(sizeof(pthread_t) * concurrency);
    for (int i = 0; i < concurrency; i++) {
        int *id = malloc(sizeof(int));
        *id = i;
        if (pthread_create(&threads[i], NULL, worker, id) != 0) {
            perror("pthread_create");
            free(id);
        }
    }

    // Wait for threads to complete
    for (int i = 0; i < concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up iptables rule if not interrupted
    if (kill_flag && !should_exit) {
        system(del_command);
        debug_print("Removed general iptables rule");
    }

    // Print final status
    printf("Completed %d/%d connections\n", atomic_load(&connection_counter), total_connections);

    // Free allocated memory
    if (server_ip) free(server_ip);
    if (server_port) free(server_port);
    if (client_ip_range) free(client_ip_range);
    if (client_port_range) free(client_port_range);
    if (source_ips) free(source_ips);
    if (source_ports) free(source_ports);
    if (targets) {
        for (int i = 0; i < num_targets; i++) free(targets[i].host);
        free(targets);
    }
    free(threads);

    return 0;
}
