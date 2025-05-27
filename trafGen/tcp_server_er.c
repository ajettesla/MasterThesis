
/*
 * High-Performance Epoll-based Multithreaded TCP Server (with iptables rule management and correct fd handling)
 * - Fix: Only apply SO_LINGER/close_with_rst() to sockets (not timerfd/pipe fds)
 * - Fix: accept4 declaration (via _GNU_SOURCE)
 * - Fix: No epoll_data_t conflict
 to run this program ./tcp_server_er -p 8000 -a 4 (accept 4) -w 4 (workers) -k (rst the connection and drop them by iptables).
 */


#define _GNU_SOURCE
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
#include <stdint.h>

#define MAX_EVENTS 4096
#define MAX_WORKERS 128
#define MAX_ACCEPTORS 64
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 8080
#define DEFAULT_ACCEPTORS 8
#define DEFAULT_WORKERS 8
#define SHUTDOWN_TIMEOUT 10
#define CONNECTION_TIMEOUT_SEC 15
#define LOG_BUFFER_SIZE 8192

/* --- Logger --- */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    char buffer[LOG_BUFFER_SIZE];
    size_t len;
    int shutdown;
} logger_t;

logger_t global_logger;

void logger_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&global_logger.lock);
    size_t avail = LOG_BUFFER_SIZE - global_logger.len - 2;
    if (avail > 0) {
        int written = vsnprintf(global_logger.buffer + global_logger.len, avail, fmt, args);
        if (written > 0 && (size_t)written < avail) {
            global_logger.len += (size_t)written;
            global_logger.buffer[global_logger.len++] = '\n';
            global_logger.buffer[global_logger.len] = 0;
        }
    }
    pthread_cond_signal(&global_logger.cond);
    pthread_mutex_unlock(&global_logger.lock);
    va_end(args);
}

void *logger_thread_func(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&global_logger.lock);
        while (global_logger.len == 0 && !global_logger.shutdown) {
            pthread_cond_wait(&global_logger.cond, &global_logger.lock);
        }
        if (global_logger.shutdown && global_logger.len == 0) {
            pthread_mutex_unlock(&global_logger.lock);
            break;
        }
        if (global_logger.len > 0) {
            fwrite(global_logger.buffer, 1, global_logger.len, stderr);
            global_logger.len = 0;
            global_logger.buffer[0] = 0;
        }
        pthread_mutex_unlock(&global_logger.lock);
    }
    return NULL;
}
#define LOG(...) logger_log(__VA_ARGS__)

/* --- Globals and flags --- */
static volatile sig_atomic_t shutdown_flag = 0;
static bool debug_mode = false;
static bool use_rst = false;
static int port = DEFAULT_PORT;
static int num_acceptors = DEFAULT_ACCEPTORS;
static int num_workers = DEFAULT_WORKERS;
static atomic_int active_connections = 0;
static atomic_int technical_error_count = 0;
static atomic_int timeout_error_count = 0;
static atomic_int total_connections_handled = 0;

/* --- Structures --- */
typedef struct {
    int epoll_fd;
    pthread_t tid;
    int idx;
    int shutdown_pipe[2];
} worker_t;

worker_t workers[MAX_WORKERS];
atomic_int next_worker = 0;

typedef struct {
    int listen_fd;
    pthread_t tid;
    int idx;
    int epoll_fd; // For epoll-based acceptor
} acceptor_t;

acceptor_t acceptors[MAX_ACCEPTORS];

/* --- Debug print --- */
void debug_print(const char *fmt, ...) {
    if (debug_mode) {
        char buf[512];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        LOG("DEBUG [Thread %p]: %s", (void*)pthread_self(), buf);
    }
}

void print_technical_error(const char *context, int fd) {
    int err = errno;
    if (fd >= 0)
        LOG("TECHNICAL ERROR: %s (fd=%d): %s (errno=%d)", context, fd, strerror(err), err);
    else
        LOG("TECHNICAL ERROR: %s: %s (errno=%d)", context, strerror(err), err);
    atomic_fetch_add(&technical_error_count, 1);
}

void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -h           Show this help message\n"
        "  -p <port>    Listen port (default: %d)\n"
        "  -a <acceptors> Number of acceptor threads (default: %d, max: %d)\n"
        "  -w <workers> Number of worker threads (default: %d, max: %d)\n"
        "  -k           Enable RST-on-close (SO_LINGER) and iptables RST rule\n"
        "  -D           Enable debug mode\n",
        prog, DEFAULT_PORT, DEFAULT_ACCEPTORS, MAX_ACCEPTORS, DEFAULT_WORKERS, MAX_WORKERS
    );
}

void handle_shutdown(int sig) {
    (void)sig;
    shutdown_flag = 1;
    debug_print("Shutdown initiated");
}

/* --- iptables management --- */
void manage_iptables(bool add) {
    if (!use_rst) return;
    const char *cmd_add = "iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    const char *cmd_del = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    int ret = system(add ? cmd_add : cmd_del);
    if (ret != 0) {
        LOG("Failed to %s iptables rule (exit=%d)", add ? "add" : "remove", ret);
    } else {
        debug_print("%s iptables rule", add ? "Added" : "Removed");
    }
}

/* --- Socket helpers --- */
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

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

/* --- Timerfd helper --- */
int make_timerfd(int secs) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) return -1;
    struct itimerspec its;
    its.it_value.tv_sec = secs;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        close(tfd);
        return -1;
    }
    return tfd;
}

/* --- Helper: check if fd is a socket (using getsockopt) --- */
bool is_fd_socket(int fd) {
    int type;
    socklen_t len = sizeof(type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
}

/* --- Worker thread main loop (EPOLLONESHOT, buffer draining, timeout) --- */
void *worker_loop(void *arg) {
    worker_t *worker = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];

    while (!shutdown_flag) {
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            print_technical_error("epoll_wait() failed", -1);
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            // Shutdown pipe signal
            if (fd == worker->shutdown_pipe[0]) {
                char buf[16];
                read(worker->shutdown_pipe[0], buf, sizeof(buf));
                debug_print("Worker %d received shutdown signal.", worker->idx);
                continue;
            }

            // If timerfd_gettime succeeds, it's a timerfd (timeout)
            struct itimerspec curr;
            if (timerfd_gettime(fd, &curr) == 0) {
                uint64_t exp;
                read(fd, &exp, sizeof(exp));
                close(fd);
                atomic_fetch_add(&timeout_error_count, 1);
                debug_print("Worker %d closed idle connection (timeout)", worker->idx);
                continue;
            }

            // Only handle sockets with close_with_rst
            if (!is_fd_socket(fd)) {
                close(fd);
                continue;
            }

            // Ready for reading
            if (ev & EPOLLIN) {
                ssize_t count;
                int drained = 0, close_conn = 0;
                while ((count = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
                    buffer[count] = 0;
                    drained = 1;
                    debug_print("Received from fd %d: '%s'", fd, buffer);
                    if (strncmp(buffer, "hello\n", 6) == 0) {
                        if (write(fd, "hello\n", 6) < 0) {
                            print_technical_error("write() failed", fd);
                        }
                    }
                    // Always close after response
                    close_conn = 1;
                }
                if (count == 0) close_conn = 1;
                else if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    close_conn = 1;
                if (close_conn) {
                    close_with_rst(fd);
                } else if (drained) {
                    // Rearm for EPOLLONESHOT
                    struct epoll_event eev = {0};
                    eev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                    eev.data.fd = fd;
                    epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, fd, &eev);
                }
            }
        }
        if (shutdown_flag) break;
    }
    debug_print("Worker %d exiting", worker->idx);
    return NULL;
}

/* --- Status reporting thread --- */
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

/* --- Acceptor thread: uses epoll for listen_fd readiness --- */
void *acceptor_loop(void *arg) {
    acceptor_t *acceptor = (acceptor_t *)arg;
    int listen_fd = acceptor->listen_fd;
    int idx = acceptor->idx;

    struct epoll_event ev = {0};
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        print_technical_error("epoll_create1() for acceptor failed", -1);
        return NULL;
    }
    acceptor->epoll_fd = epfd;

    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        print_technical_error("epoll_ctl(acceptor) failed", listen_fd);
        close(epfd);
        return NULL;
    }

    struct epoll_event events[8];
    while (!shutdown_flag) {
        int n = epoll_wait(epfd, events, 8, 1000); // 1s timeout
        if (n < 0) {
            if (errno == EINTR) continue;
            print_technical_error("acceptor epoll_wait() failed", -1);
            break;
        }
        if (shutdown_flag) break;
        for (int j = 0; j < n; ++j) {
            if (!(events[j].events & EPOLLIN)) continue;
            while (1) {
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);
                int client_fd = accept4(listen_fd, (struct sockaddr*)&caddr, &clen, SOCK_NONBLOCK);
                if (client_fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    if (errno == EINTR)
                        continue;
                    print_technical_error("accept4() failed", listen_fd);
                    break;
                }
                int widx = atomic_fetch_add(&next_worker, 1) % num_workers;
                struct epoll_event ce = {0};
                ce.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                ce.data.fd = client_fd;
                if (epoll_ctl(workers[widx].epoll_fd, EPOLL_CTL_ADD, client_fd, &ce) < 0) {
                    print_technical_error("epoll_ctl(ADD) failed", client_fd);
                    close_with_rst(client_fd);
                    continue;
                }
                // Setup timerfd for this client for timeout
                int tfd = make_timerfd(CONNECTION_TIMEOUT_SEC);
                if (tfd >= 0) {
                    struct epoll_event tev = {0};
                    tev.events = EPOLLIN;
                    tev.data.fd = tfd;
                    epoll_ctl(workers[widx].epoll_fd, EPOLL_CTL_ADD, tfd, &tev);
                }
                atomic_fetch_add(&active_connections, 1);
                atomic_fetch_add(&total_connections_handled, 1);
                debug_print("Acceptor %d assigned fd %d to worker %d", idx, client_fd, widx);
            }
        }
    }
    close(epfd);
    debug_print("Acceptor %d exiting", idx);
    return NULL;
}

/* --- Main --- */
int main(int argc, char *argv[]) {
    int opt;
    // Logger init
    pthread_mutex_init(&global_logger.lock, NULL);
    pthread_cond_init(&global_logger.cond, NULL);
    global_logger.len = 0;
    global_logger.shutdown = 0;
    pthread_t logger_tid;
    pthread_create(&logger_tid, NULL, logger_thread_func, NULL);

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "hp:a:w:kD")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'a':
                num_acceptors = atoi(optarg);
                if (num_acceptors < 1 || num_acceptors > MAX_ACCEPTORS) {
                    fprintf(stderr, "Invalid acceptor count. Must be 1-%d.\n", MAX_ACCEPTORS);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'w':
                num_workers = atoi(optarg);
                if (num_workers < 1 || num_workers > MAX_WORKERS) {
                    fprintf(stderr, "Invalid worker count. Must be 1-%d.\n", MAX_WORKERS);
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

    debug_print("Starting server with port=%d, acceptors=%d, workers=%d, RST=%d, debug=%d",
        port, num_acceptors, num_workers, use_rst, debug_mode);

    // If RST-on-close enabled, add iptables rule
    manage_iptables(true);

    // SIGINT for shutdown
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigaction(SIGINT, &sa, NULL);

    // Create listening sockets for each acceptor
    for (int i = 0; i < num_acceptors; ++i) {
        acceptors[i].listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (acceptors[i].listen_fd < 0) {
            print_technical_error("socket() failed", -1);
            exit(EXIT_FAILURE);
        }
        int optval = 1;
        setsockopt(acceptors[i].listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        setsockopt(acceptors[i].listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
        if (bind(acceptors[i].listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            print_technical_error("bind() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        if (listen(acceptors[i].listen_fd, 4096) < 0) {
            print_technical_error("listen() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        if (make_socket_non_blocking(acceptors[i].listen_fd) < 0) {
            print_technical_error("make_socket_non_blocking() failed", acceptors[i].listen_fd);
            close(acceptors[i].listen_fd);
            exit(EXIT_FAILURE);
        }
        acceptors[i].idx = i;
    }

    // Acceptor threads
    for (int i = 0; i < num_acceptors; ++i) {
        if (pthread_create(&acceptors[i].tid, NULL, acceptor_loop, &acceptors[i]) != 0) {
            print_technical_error("pthread_create() failed for acceptor", -1);
            exit(EXIT_FAILURE);
        }
    }

    // Worker threads
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
        make_socket_non_blocking(workers[i].shutdown_pipe[0]);
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

    // Status reporting thread
    pthread_t status_tid;
    if (pthread_create(&status_tid, NULL, status_thread_func, NULL) != 0) {
        print_technical_error("pthread_create() failed for status thread", -1);
        exit(EXIT_FAILURE);
    }

    // Main: wait for shutdown
    while (!shutdown_flag) {
        sleep(1);
    }
    debug_print("Server shutting down.");

    // Close listening sockets
    for (int i = 0; i < num_acceptors; ++i) {
        close(acceptors[i].listen_fd);
    }

    // Join acceptors
    for (int i = 0; i < num_acceptors; ++i) {
        pthread_join(acceptors[i].tid, NULL);
    }

    // Wake all workers
    for (int i = 0; i < num_workers; ++i) {
        write(workers[i].shutdown_pipe[1], "x", 1);
    }
    for (int i = 0; i < num_workers; ++i) {
        pthread_join(workers[i].tid, NULL);
        close(workers[i].epoll_fd);
        close(workers[i].shutdown_pipe[0]);
        close(workers[i].shutdown_pipe[1]);
    }

    pthread_join(status_tid, NULL);

    // Remove iptables rule, if set
    manage_iptables(false);

    // Logger shutdown
    pthread_mutex_lock(&global_logger.lock);
    global_logger.shutdown = 1;
    pthread_cond_signal(&global_logger.cond);
    pthread_mutex_unlock(&global_logger.lock);
    pthread_join(logger_tid, NULL);

    printf("\n--- Server statistics ---\n");
    printf("Active connections at shutdown: %d\n", atomic_load(&active_connections));
    printf("Technical error count: %d\n", atomic_load(&technical_error_count));
    printf("Timeout error count:   %d\n", atomic_load(&timeout_error_count));
    printf("Total connections handled: %d\n", atomic_load(&total_connections_handled));
    printf("------------------------\n");
    return 0;
}

/* --- NOTES ---
- Only calls close_with_rst() on sockets; timerfds/pipes are closed directly.
- If RST-on-close is enabled, the iptables rule is added/removed at startup/shutdown.
- _GNU_SOURCE enables accept4() declaration.
- No epoll_data_t conflict.
*/
