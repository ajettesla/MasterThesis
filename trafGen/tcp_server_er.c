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
#include <sys/timerfd.h>
#include <errno.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

#define MAX_EVENTS      1024
#define MAX_THREADS     8
#define BUFFER_SIZE     1024
#define DEFAULT_PORT    8080
#define SHUTDOWN_TIMEOUT 10
#define MAX_CONNECTIONS 10000

// --------------------------------
// Global variables & structs
// --------------------------------
static volatile sig_atomic_t shutdown_flag = 0;
static bool debug_mode = false;
static int port = DEFAULT_PORT;
static int num_threads = 4;

static atomic_int active_connections = 0;

// Per-connection structure
typedef struct connection {
    int fd;
    char buf[BUFFER_SIZE];
    int buf_used;
    bool closed;
} connection_t;

// Per-thread context
typedef struct worker_ctx {
    int epoll_fd;
    int notify_fd; // For waking up the thread
    pthread_t thread;
    connection_t *conns[MAX_CONNECTIONS];
    int conn_count;
} worker_ctx_t;

static worker_ctx_t *worker_pool = NULL;

// --------------------------------
// Utility functions
// --------------------------------
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

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// --------------------------------
// Signal handler
// --------------------------------
void handle_shutdown(int sig) {
    shutdown_flag = 1;
}

// --------------------------------
// Worker thread main
// --------------------------------
void *worker_main(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    struct epoll_event events[MAX_EVENTS];

    while (!shutdown_flag) {
        int n = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            // Handle notify fd (for waking up)
            if (fd == ctx->notify_fd) {
                char buf[8];
                read(ctx->notify_fd, buf, sizeof(buf));
                continue;
            }

            // Find connection object
            connection_t *conn = NULL;
            for (int ci = 0; ci < ctx->conn_count; ++ci) {
                if (ctx->conns[ci] && ctx->conns[ci]->fd == fd) {
                    conn = ctx->conns[ci];
                    break;
                }
            }
            if (!conn) {
                debug_print("No connection found for fd %d", fd);
                close(fd);
                continue;
            }

            // Read data
            ssize_t r = read(fd, conn->buf, BUFFER_SIZE - 1);
            if (r <= 0) {
                debug_print("Closing fd %d", fd);
                close(fd);
                conn->closed = true;
                atomic_fetch_sub(&active_connections, 1);
                continue;
            }
            conn->buf[r] = '\0';
            debug_print("Received from fd %d: '%s'", fd, conn->buf);

            // Simple protocol
            if (strncmp(conn->buf, "hello\n", 6) == 0) {
                const char *resp = "hello\n";
                write(fd, resp, strlen(resp));
            }
            // Always close after response for this example
            close(fd);
            conn->closed = true;
            atomic_fetch_sub(&active_connections, 1);
        }

        // Cleanup closed conns
        int out = 0;
        for (int ci = 0; ci < ctx->conn_count; ++ci) {
            if (ctx->conns[ci] && !ctx->conns[ci]->closed) {
                ctx->conns[out++] = ctx->conns[ci];
            } else {
                free(ctx->conns[ci]);
            }
        }
        ctx->conn_count = out;
    }
    return NULL;
}

// --------------------------------
// Accept thread (main)
// --------------------------------
void distribute_connection(int client_fd, int idx) {
    worker_ctx_t *ctx = &worker_pool[idx];
    set_nonblocking(client_fd);

    connection_t *conn = calloc(1, sizeof(connection_t));
    conn->fd = client_fd;
    conn->closed = false;
    ctx->conns[ctx->conn_count++] = conn;

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

    // Wake up worker thread if needed
    uint64_t one = 1;
    write(ctx->notify_fd, &one, sizeof(one));
    atomic_fetch_add(&active_connections, 1);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:t:D")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 't': num_threads = atoi(optarg); break;
            case 'D': debug_mode = true; break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t threads] [-D]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;

    // Raise fd rlimit if needed (ulimit -n 20000, or setrlimit)

    signal(SIGINT, handle_shutdown);

    // Listener socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }
    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    set_nonblocking(server_fd);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_fd); exit(EXIT_FAILURE);
    }
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen"); close(server_fd); exit(EXIT_FAILURE);
    }

    // Worker pool
    worker_pool = calloc(num_threads, sizeof(worker_ctx_t));
    for (int i = 0; i < num_threads; ++i) {
        int epfd = epoll_create1(0);
        int fds[2];
        pipe(fds);
        worker_pool[i].epoll_fd = epfd;
        worker_pool[i].notify_fd = fds[0];
        worker_pool[i].conn_count = 0;
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = fds[0];
        epoll_ctl(epfd, EPOLL_CTL_ADD, fds[0], &ev);
        pthread_create(&worker_pool[i].thread, NULL, worker_main, &worker_pool[i]);
    }

    // Main accept loop: distribute to workers round-robin
    int rr = 0;
    while (!shutdown_flag) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000); // avoid busy loop
                continue;
            }
            perror("accept");
            break;
        }
        distribute_connection(client_fd, rr);
        rr = (rr + 1) % num_threads;
    }

    // Shutdown: join threads
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(worker_pool[i].thread, NULL);
        close(worker_pool[i].epoll_fd);
        close(worker_pool[i].notify_fd);
    }
    close(server_fd);
    free(worker_pool);

    debug_print("Server shutdown complete");
    return 0;
}
