/*
 * High-Performance Epoll-based Multithreaded TCP Server
 * Features:
 *  - Immediate, clean shutdown on Ctrl+C (SIGINT)
 *  - Status message every 30s to stdout
 *  - Other features unchanged from before
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/eventfd.h>

#define MAX_EVENTS 4096
#define MAX_WORKERS 128
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 8080
#define DEFAULT_THREADS 16
#define SHUTDOWN_TIMEOUT 10

// Global flags and variables
static volatile sig_atomic_t shutdown_flag = 0;
static bool debug_mode = false;
static bool use_rst = false; // if true, both RST-on-close and iptables are enabled
static int port = DEFAULT_PORT;
static int num_workers = DEFAULT_THREADS;
static atomic_int active_connections = 0;
static atomic_int technical_error_count = 0;
static atomic_int timeout_error_count = 0;
static atomic_int total_connections_handled = 0;

typedef struct {
    int epoll_fd;
    pthread_t tid;
    int idx;
    int shutdown_pipe[2];
} worker_t;

worker_t workers[MAX_WORKERS];
atomic_int next_worker = 0;

void debug_print(const char *fmt, ...) {
    if (debug_mode) {
        fprintf(stderr, "DEBUG [Thread %p]: ", (void*)pthread_self());
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
    }
}

// Print details of technical errors, increment counter
void print_technical_error(const char *context, int fd) {
    int err = errno;
    fprintf(stderr, "TECHNICAL ERROR: %s", context);
    if (fd >= 0) {
        fprintf(stderr, " (fd=%d)", fd);
    }
    fprintf(stderr, ": %s (errno=%d)\n", strerror(err), err);
    atomic_fetch_add(&technical_error_count, 1);
}

// Add or remove iptables rule to drop outbound TCP RST packets
void manage_iptables(bool add) {
    if (!use_rst) return;
    const char *cmd_add = "iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    const char *cmd_del = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    int ret = system(add ? cmd_add : cmd_del);
    if (ret != 0) {
        fprintf(stderr, "Failed to %s iptables rule\n", add ? "add" : "remove");
    } else {
        debug_print("%s iptables rule", add ? "Added" : "Removed");
    }
}

// Signal handler for graceful shutdown (SIGINT)
void handle_shutdown(int sig) {
    (void)sig;
    shutdown_flag = 1;
    debug_print("Shutdown initiated, signaling all threads.");
}

// Set a socket FD to non-blocking mode
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Close a client socket with RST if enabled, always decrements active_connections
void close_with_rst(int fd) {
    if (use_rst) {
        struct linger sl = {1, 0};
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0) {
            print_technical_error("setsockopt(SO_LINGER) failed", fd);
        } else {
            debug_print("Sent RST on fd %d", fd);
        }
    }
    if (close(fd) < 0) {
        print_technical_error("close() failed", fd);
    }
    atomic_fetch_sub(&active_connections, 1);
}

// Worker thread function: Each worker owns an epoll instance and a shutdown pipe
void *worker_loop(void *arg) {
    worker_t *worker = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];

    while (!shutdown_flag) {
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            print_technical_error("epoll_wait() failed", -1);
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == worker->shutdown_pipe[0]) {
                // Drain the pipe
                char buf[16];
                read(worker->shutdown_pipe[0], buf, sizeof(buf));
                debug_print("Worker %d received shutdown signal.", worker->idx);
                break;
            }
            if (events[i].events & EPOLLIN) {
                ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
                if (count < 0) {
                    print_technical_error("read() failed", fd);
                    close_with_rst(fd);
                } else if (count == 0) {
                    debug_print("Closing fd %d (EOF)", fd);
                    close_with_rst(fd);
                } else {
                    buffer[count] = 0;
                    debug_print("Received from fd %d: '%s'", fd, buffer);
                    if (strncmp(buffer, "hello\n", 6) == 0) {
                        if (write(fd, "hello\n", 6) < 0) {
                            print_technical_error("write() failed", fd);
                        }
                    }
                    close_with_rst(fd);
                }
            }
        }
        if (shutdown_flag) {
            break;
        }
    }
    debug_print("Worker %d exiting", worker->idx);
    return NULL;
}

// Status thread: print connection stats every 30 seconds, but exit promptly on shutdown
void *status_thread_func(void *arg) {
    (void)arg;
    int elapsed = 0;
    while (!shutdown_flag) {
        sleep(1);
        elapsed++;
        if (shutdown_flag) break;
        if (elapsed >= 30) {
            int total = atomic_load(&total_connections_handled);
            printf("[STATUS] %d connections handled so far. Server is running happily!\n", total);
            fflush(stdout);
            elapsed = 0;
        }
    }
    return NULL;
}

// Print help/usage message
void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -h           Show this help message\n"
        "  -p <port>    Listen port (default: %d)\n"
        "  -t <threads> Number of worker threads (default: %d, max: %d)\n"
        "  -k           Enable RST-on-close (SO_LINGER) and iptables RST rule\n"
        "  -D           Enable debug mode\n",
        prog, DEFAULT_PORT, DEFAULT_THREADS, MAX_WORKERS
    );
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "hp:t:kD")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 't':
                num_workers = atoi(optarg);
                if (num_workers < 1 || num_workers > MAX_WORKERS) {
                    fprintf(stderr, "Invalid thread count. Must be 1-%d.\n", MAX_WORKERS);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'k':
                use_rst = true;
                break;
            case 'D':
                debug_mode = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                exit(opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    debug_print("Starting server with port=%d, threads=%d, RST+iptables=%d, debug=%d",
        port, num_workers, use_rst, debug_mode);

    // Set up signal handler for graceful shutdown (Ctrl+C)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigaction(SIGINT, &sa, NULL);

    // Add iptables rule for RST if enabled
    manage_iptables(true);

    // Create the listening socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        print_technical_error("socket() failed", -1);
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        print_technical_error("setsockopt(SO_REUSEADDR) failed", listen_fd);
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0)
        print_technical_error("setsockopt(SO_REUSEPORT) failed", listen_fd);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        print_technical_error("bind() failed", listen_fd);
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, 4096) < 0) {
        print_technical_error("listen() failed", listen_fd);
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    if (make_socket_non_blocking(listen_fd) < 0) {
        print_technical_error("make_socket_non_blocking() failed", listen_fd);
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Create worker threads and their epoll instances, with shutdown pipe
    for (int i = 0; i < num_workers; ++i) {
        workers[i].epoll_fd = epoll_create1(0);
        workers[i].idx = i;
        if (workers[i].epoll_fd < 0) {
            print_technical_error("epoll_create1() failed", -1);
            exit(EXIT_FAILURE);
        }
        if (pipe(workers[i].shutdown_pipe) != 0) {
            print_technical_error("pipe() failed for shutdown pipe", -1);
            exit(EXIT_FAILURE);
        }
        // Set read end non-blocking (not strictly needed, but good practice)
        make_socket_non_blocking(workers[i].shutdown_pipe[0]);
        // Add shutdown pipe read end to epoll
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = workers[i].shutdown_pipe[0];
        if (epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, workers[i].shutdown_pipe[0], &ev) < 0) {
            print_technical_error("epoll_ctl(ADD shutdown pipe) failed", workers[i].shutdown_pipe[0]);
            exit(EXIT_FAILURE);
        }
        if (pthread_create(&workers[i].tid, NULL, worker_loop, &workers[i]) != 0) {
            print_technical_error("pthread_create() failed", -1);
            exit(EXIT_FAILURE);
        }
    }

    // Start status reporting thread
    pthread_t status_tid;
    pthread_create(&status_tid, NULL, status_thread_func, NULL);

    // Main accept loop: Accept new client connections and distribute to worker threads
    while (!shutdown_flag) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client_fd = accept4(listen_fd, (struct sockaddr*)&caddr, &clen, SOCK_NONBLOCK);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(500);
                continue;
            } else if (errno == EINTR) {
                continue;
            }
            print_technical_error("accept4() failed", listen_fd);
            break;
        }
        int widx = atomic_fetch_add(&next_worker, 1) % num_workers;
        struct epoll_event ev = {0};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        if (epoll_ctl(workers[widx].epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            print_technical_error("epoll_ctl(ADD) failed", client_fd);
            close_with_rst(client_fd);
            continue;
        }
        atomic_fetch_add(&active_connections, 1);
        atomic_fetch_add(&total_connections_handled, 1);
        debug_print("Accepted and assigned fd %d to worker %d", client_fd, widx);
    }

    debug_print("Server shutting down, closing listen_fd");
    close(listen_fd);

    // Signal all workers to wake up immediately via shutdown pipe
    for (int i = 0; i < num_workers; ++i) {
        // Write at least 1 byte to wake them up
        write(workers[i].shutdown_pipe[1], "x", 1);
    }

    // Wait for all worker threads to finish
    for (int i = 0; i < num_workers; ++i) {
        pthread_join(workers[i].tid, NULL);
        close(workers[i].epoll_fd);
        close(workers[i].shutdown_pipe[0]);
        close(workers[i].shutdown_pipe[1]);
    }

    // Join the status reporting thread
    pthread_join(status_tid, NULL);

    manage_iptables(false);
    debug_print("Server shutdown complete");

    printf("\n--- Server statistics ---\n");
    printf("Active connections at shutdown: %d\n", atomic_load(&active_connections));
    printf("Technical error count: %d\n", atomic_load(&technical_error_count));
    printf("Timeout error count:   %d\n", atomic_load(&timeout_error_count));
    printf("Total connections handled: %d\n", atomic_load(&total_connections_handled));
    printf("------------------------\n");
    return 0;
}
