/*
 * High-Performance Epoll-based Multithreaded TCP Server
 * Features:
 *  - Immediate, clean shutdown on Ctrl+C (SIGINT)
 *  - Status message every 30s to stdout
 *  - RST-on-close option with iptables rule
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

// Constants
#define MAX_EVENTS 4096
#define MAX_WORKERS 128
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 8080
#define DEFAULT_ACCEPTORS 8
#define MAX_ACCEPTORS 64
#define SHUTDOWN_TIMEOUT 10

// Global flags and variables
static volatile sig_atomic_t shutdown_flag = 0;         // Flag to indicate shutdown
static bool debug_mode = false;                         // Debug mode flag
static bool use_rst = false;                            // RST-on-close flag
static int port = DEFAULT_PORT;                         // Listening port
static int num_acceptors = DEFAULT_ACCEPTORS;           // Number of acceptor threads
static int num_workers;                                 // Number of worker threads
static atomic_int active_connections = 0;               // Active connections counter
static atomic_int technical_error_count = 0;            // Technical errors counter
static atomic_int timeout_error_count = 0;              // Timeout errors counter
static atomic_int total_connections_handled = 0;        // Total connections handled

// Worker thread structure
typedef struct {
    int epoll_fd;               // epoll instance fd
    pthread_t tid;              // Worker thread id
    int idx;                    // Worker index
    int shutdown_pipe[2];       // Pipe to signal shutdown
} worker_t;

worker_t workers[MAX_WORKERS];  // Array of workers
atomic_int next_worker = 0;     // For round-robin worker assignment

// Acceptor thread structure
typedef struct {
    int listen_fd;              // Listening socket fd
    pthread_t tid;              // Acceptor thread id
    int idx;                    // Acceptor index
} acceptor_t;

acceptor_t acceptors[MAX_ACCEPTORS]; // Array of acceptors

// Print debug message if debug mode is active
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

// Print and count technical errors
void print_technical_error(const char *context, int fd) {
    int err = errno;
    fprintf(stderr, "TECHNICAL ERROR: %s", context);
    if (fd >= 0) {
        fprintf(stderr, " (fd=%d)", fd);
    }
    fprintf(stderr, ": %s (errno=%d)\n", strerror(err), err);
    atomic_fetch_add(&technical_error_count, 1);
}

// Manage iptables rule for dropping outgoing RST packets
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

// SIGINT signal handler for graceful shutdown
void handle_shutdown(int sig) {
    (void)sig; // unused parameter
    shutdown_flag = 1;
    debug_print("Shutdown initiated.");
}

// Set a socket as non-blocking
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Close a TCP socket, optionally sending RST using SO_LINGER
void close_with_rst(int fd) {
    if (use_rst) {
        struct linger sl = {1, 0}; // 0 timeout = send RST
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

// Worker thread main loop
void *worker_loop(void *arg) {
    worker_t *worker = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];

    while (!shutdown_flag) {
        // Wait for events on sockets
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue; // interrupted by signal
            print_technical_error("epoll_wait() failed", -1);
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            // Check for shutdown signal
            if (fd == worker->shutdown_pipe[0]) {
                char buf[16];
                read(worker->shutdown_pipe[0], buf, sizeof(buf));
                debug_print("Worker %d received shutdown signal.", worker->idx);
                break;
            }
            // Handle readable socket
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
                    // Simple echo for "hello"
                    if (strncmp(buffer, "hello\n", 6) == 0) {
                        if (write(fd, "hello\n", 6) < 0) {
                            print_technical_error("write() failed", fd);
                        }
                    }
                    // Always close after response
                    close_with_rst(fd);
                }
            }
        }
        if (shutdown_flag) break;
    }
    debug_print("Worker %d exiting", worker->idx);
    return NULL;
}

// Periodic status reporting thread
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

// Print command-line usage message
void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -h           Show this help message\n"
        "  -p <port>    Listen port (default: %d)\n"
        "  -t <threads> Number of acceptor threads (default: %d, max: %d)\n"
        "               Data handling threads will be twice this number.\n"
        "  -k           Enable RST-on-close (SO_LINGER) and iptables RST rule\n"
        "  -D           Enable debug mode\n",
        prog, DEFAULT_PORT, DEFAULT_ACCEPTORS, MAX_ACCEPTORS
    );
}

// Acceptor thread main loop: accept new clients and assign to workers
void *acceptor_loop(void *arg) {
    acceptor_t *acceptor = (acceptor_t *)arg;
    int listen_fd = acceptor->listen_fd;
    int idx = acceptor->idx;

    while (!shutdown_flag) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        // Accept a new connection (non-blocking)
        int client_fd = accept4(listen_fd, (struct sockaddr*)&caddr, &clen, SOCK_NONBLOCK);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(500); // No pending connections, sleep briefly
                continue;
            } else if (errno == EINTR) {
                continue; // interrupted by signal
            }
            print_technical_error("accept4() failed", listen_fd);
            break;
        }
        // Assign client to the next worker thread in round-robin fashion
        int widx = atomic_fetch_add(&next_worker, 1) % num_workers;
        struct epoll_event ev = {0};
        ev.events = EPOLLIN | EPOLLET; // Edge-triggered read
        ev.data.fd = client_fd;
        if (epoll_ctl(workers[widx].epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            print_technical_error("epoll_ctl(ADD) failed", client_fd);
            close_with_rst(client_fd);
            continue;
        }
        atomic_fetch_add(&active_connections, 1);
        atomic_fetch_add(&total_connections_handled, 1);
        debug_print("Acceptor %d accepted and assigned fd %d to worker %d", idx, client_fd, widx);
    }
    debug_print("Acceptor %d exiting", idx);
    return NULL;
}

// Main program entry point
int main(int argc, char *argv[]) {
    int opt;
    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "hp:t:kD")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 't':
                num_acceptors = atoi(optarg);
                if (num_acceptors < 1 || num_acceptors > MAX_ACCEPTORS) {
                    fprintf(stderr, "Invalid acceptor count. Must be 1-%d.\n", MAX_ACCEPTORS);
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

    // Set number of worker threads (twice number of acceptors)
    num_workers = 2 * num_acceptors;

    debug_print("Starting server with port=%d, acceptors=%d, workers=%d, RST+iptables=%d, debug=%d",
        port, num_acceptors, num_workers, use_rst, debug_mode);

    // Set up signal handler for graceful shutdown (Ctrl+C)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigaction(SIGINT, &sa, NULL);

    // Add iptables rule for RST if enabled
    manage_iptables(true);

    // Create listening sockets for each acceptor
    for (int i = 0; i < num_acceptors; ++i) {
        // Create TCP socket
        acceptors[i].listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (acceptors[i].listen_fd < 0) {
            print_technical_error("socket() failed", -1);
            exit(EXIT_FAILURE);
        }
        int optval = 1;
        // Allow address and port reuse for multiple acceptors
        if (setsockopt(acceptors[i].listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
            print_technical_error("setsockopt(SO_REUSEADDR) failed", acceptors[i].listen_fd);
        if (setsockopt(acceptors[i].listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0)
            print_technical_error("setsockopt(SO_REUSEPORT) failed", acceptors[i].listen_fd);
        // Bind socket to the desired port
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
        if (bind(acceptors[i].listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            print_technical_error("bind() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        // Start listening
        if (listen(acceptors[i].listen_fd, 4096) < 0) {
            print_technical_error("listen() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        // Set listen socket as non-blocking
        if (make_socket_non_blocking(acceptors[i].listen_fd) < 0) {
            print_technical_error("make_socket_non_blocking() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        acceptors[i].idx = i;
    }

    // Create acceptor threads
    for (int i = 0; i < num_acceptors; ++i) {
        if (pthread_create(&acceptors[i].tid, NULL, acceptor_loop, &acceptors[i]) != 0) {
            print_technical_error("pthread_create() failed for acceptor", -1);
            exit(EXIT_FAILURE);
        }
    }

    // Create worker threads and their epoll instances, with shutdown pipes
    for (int i = 0; i < num_workers; ++i) {
        workers[i].epoll_fd = epoll_create1(0);
        if (workers[i].epoll_fd < 0) {
            print_technical_error("epoll_create1() failed", -1);
            exit(EXIT_FAILURE);
        }
        workers[i].idx = i;
        if (pipe(workers[i].shutdown_pipe) != 0) {
            print_technical_error("pipe() failed for shutdown pipe", -1);
            exit(EXIT_FAILURE);
        }
        // Make read end non-blocking
        make_socket_non_blocking(workers[i].shutdown_pipe[0]);
        // Add shutdown pipe to epoll instance
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = workers[i].shutdown_pipe[0];
        if (epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, workers[i].shutdown_pipe[0], &ev) < 0) {
            print_technical_error("epoll_ctl(ADD shutdown pipe) failed", workers[i].shutdown_pipe[0]);
            exit(EXIT_FAILURE);
        }
        // Start worker thread
        if (pthread_create(&workers[i].tid, NULL, worker_loop, &workers[i]) != 0) {
            print_technical_error("pthread_create() failed", -1);
            exit(EXIT_FAILURE);
        }
    }

    // Start status reporting thread
    pthread_t status_tid;
    if (pthread_create(&status_tid, NULL, status_thread_func, NULL) != 0) {
        print_technical_error("pthread_create() failed for status thread", -1);
        exit(EXIT_FAILURE);
    }

    // Main thread: wait for shutdown signal
    while (!shutdown_flag) {
        sleep(1);
    }

    debug_print("Server shutting down.");

    // Close all listening sockets to interrupt acceptors
    for (int i = 0; i < num_acceptors; ++i) {
        close(acceptors[i].listen_fd);
    }

    // Join all acceptor threads
    for (int i = 0; i < num_acceptors; ++i) {
        pthread_join(acceptors[i].tid, NULL);
    }

    // Signal all workers to wake up immediately via shutdown pipe
    for (int i = 0; i < num_workers; ++i) {
        write(workers[i].shutdown_pipe[1], "x", 1);
    }

    // Join all worker threads and clean up
    for (int i = 0; i < num_workers; ++i) {
        pthread_join(workers[i].tid, NULL);
        close(workers[i].epoll_fd);
        close(workers[i].shutdown_pipe[0]);
        close(workers[i].shutdown_pipe[1]);
    }

    // Join the status reporting thread
    pthread_join(status_tid, NULL);

    // Remove iptables rule, if set
    manage_iptables(false);
    debug_print("Server shutdown complete");

    // Print final statistics
    printf("\n--- Server statistics ---\n");
    printf("Active connections at shutdown: %d\n", atomic_load(&active_connections));
    printf("Technical error count: %d\n", atomic_load(&technical_error_count));
    printf("Timeout error count:   %d\n", atomic_load(&timeout_error_count));
    printf("Total connections handled: %d\n", atomic_load(&total_connections_handled));
    printf("------------------------\n");
    return 0;
}
