#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

#define MAX_EVENTS      4096
#define MAX_THREADS     32
#define BUFFER_SIZE     512
#define DEFAULT_PORT    8080
#define MAX_CONCURRENCY 10000

// Global flags
static volatile sig_atomic_t shutdown_flag = 0;
static bool debug_mode = false;
static bool drop_rst = false;
static int port = DEFAULT_PORT;
static int num_threads = 8;

static atomic_int active_connections = 0;
static atomic_long total_handled = 0;

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

void handle_shutdown(int sig) {
    shutdown_flag = 1;
}

void manage_iptables(bool add) {
    if (!drop_rst) return;
    const char *cmd_add = "iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    const char *cmd_del = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP";
    int ret = system(add ? cmd_add : cmd_del);
    if (ret != 0) {
        fprintf(stderr, "Failed to %s iptables rule\n", add ? "add" : "remove");
    } else {
        debug_print("%s iptables rule", add ? "Added" : "Removed");
    }
}

// Dynamic connection pool node
typedef struct conn_node {
    int fd;
    char *buf;
    int buf_used;
    struct conn_node *next;
} conn_node_t;

// Per-thread context
typedef struct worker_ctx {
    int server_fd;
    int epoll_fd;
    pthread_t thread;
    conn_node_t *conn_list; // Linked list of connections
    int conn_count;
} worker_ctx_t;

static worker_ctx_t *worker_pool = NULL;

// Add a connection to the dynamic pool (linked list)
conn_node_t* add_connection(worker_ctx_t *ctx, int fd) {
    conn_node_t *node = calloc(1, sizeof(conn_node_t));
    if (!node) return NULL;
    node->fd = fd;
    node->buf = malloc(BUFFER_SIZE);
    node->buf_used = 0;
    node->next = ctx->conn_list;
    ctx->conn_list = node;
    ctx->conn_count++;
    return node;
}

// Remove and free a connection node (by fd)
void remove_connection(worker_ctx_t *ctx, int fd) {
    conn_node_t *prev = NULL, *curr = ctx->conn_list;
    while (curr) {
        if (curr->fd == fd) {
            if (prev)
                prev->next = curr->next;
            else
                ctx->conn_list = curr->next;
            if (curr->buf) free(curr->buf);
            free(curr);
            ctx->conn_count--;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

// Find a connection node by fd
conn_node_t* find_connection(worker_ctx_t *ctx, int fd) {
    conn_node_t *curr = ctx->conn_list;
    while (curr) {
        if (curr->fd == fd) return curr;
        curr = curr->next;
    }
    return NULL;
}

// Accept as many connections as possible (non-blocking)
void accept_new_connections(worker_ctx_t *ctx) {
    while (1) {
        int client_fd = accept(ctx->server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break; // No more to accept
            perror("accept");
            break;
        }
        set_nonblocking(client_fd);
        struct epoll_event ev = {0};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            perror("epoll_ctl add client_fd");
            close(client_fd); // FD leak protection
            continue;
        }
        if (!add_connection(ctx, client_fd)) {
            debug_print("Could not add connection to pool");
            close(client_fd); // FD leak protection
            continue;
        }
        atomic_fetch_add(&active_connections, 1);
    }
}

// Worker thread main with SO_REUSEPORT and dynamic pool
void *worker_main(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    struct epoll_event events[MAX_EVENTS];

    while (!shutdown_flag) {
        int n = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == ctx->server_fd) {
                accept_new_connections(ctx);
                continue;
            }
            conn_node_t *conn = find_connection(ctx, fd);
            if (!conn) {
                debug_print("No connection for fd %d", fd);
                epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                continue;
            }
            ssize_t r = read(fd, conn->buf, BUFFER_SIZE - 1);
            if (r <= 0) {
                debug_print("Closing fd %d", fd);
                epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                remove_connection(ctx, fd);
                atomic_fetch_sub(&active_connections, 1);
                continue;
            }
            conn->buf[r] = '\0';
            debug_print("Received: '%s'", conn->buf);
            if (strncmp(conn->buf, "hello\n", 6) == 0) {
                const char *resp = "hello\n";
                write(fd, resp, strlen(resp));
            }
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
            remove_connection(ctx, fd);
            atomic_fetch_sub(&active_connections, 1);
            atomic_fetch_add(&total_handled, 1);
        }
    }
    // Cleanup all connections on shutdown
    conn_node_t *curr = ctx->conn_list;
    while (curr) {
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
        close(curr->fd);
        conn_node_t *next = curr->next;
        if (curr->buf) free(curr->buf);
        free(curr);
        curr = next;
    }
    ctx->conn_list = NULL;
    return NULL;
}

int create_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    set_nonblocking(fd);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        close(fd); return -1;
    }
    return fd;
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:t:kD")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 't': num_threads = atoi(optarg); break;
            case 'k': drop_rst = true; break;
            case 'D': debug_mode = true; break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t threads] [-k] [-D]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (num_threads < 1) num_threads = 1;

    signal(SIGINT, handle_shutdown);

    manage_iptables(true);

    worker_pool = calloc(num_threads, sizeof(worker_ctx_t));
    for (int i = 0; i < num_threads; ++i) {
        int server_fd = create_server_socket(port);
        if (server_fd < 0) {
            fprintf(stderr, "Failed to create server socket for worker %d\n", i);
            exit(EXIT_FAILURE);
        }
        worker_pool[i].server_fd = server_fd;
        worker_pool[i].epoll_fd = epoll_create1(0);
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = server_fd;
        if (epoll_ctl(worker_pool[i].epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
            perror("epoll_ctl add server_fd");
            exit(EXIT_FAILURE);
        }
        worker_pool[i].conn_list = NULL;
        worker_pool[i].conn_count = 0;
        pthread_create(&worker_pool[i].thread, NULL, worker_main, &worker_pool[i]);
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(worker_pool[i].thread, NULL);
        close(worker_pool[i].epoll_fd);
        close(worker_pool[i].server_fd);
    }
    free(worker_pool);

    manage_iptables(false);

    debug_print("Server shutdown complete, handled %ld connections", atomic_load(&total_handled));
    return 0;
}
