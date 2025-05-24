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
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

#define MAX_EVENTS 10
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 8080
#define DEFAULT_THREADS 2
#define SHUTDOWN_TIMEOUT 10

// Global flags
static volatile sig_atomic_t shutdown_flag = 0;
static bool debug_mode = false;
static bool drop_rst = false;
static bool use_rst = false;
static int port = DEFAULT_PORT;
static int initial_threads = DEFAULT_THREADS;

// Thread-safe connection counter
static atomic_int active_connections = 0;

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

void handle_shutdown(int sig) {
    if (shutdown_flag == 0) {
        shutdown_flag = 1;
        debug_print("Shutdown initiated, waiting 10 seconds for connections to close");
    }
}

void *worker_thread(void *arg) {
    int server_fd = *(int *)arg;
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return NULL;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];

    while (!shutdown_flag) {
        debug_print("Waiting to accept connection");
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("accept");
            break;
        }
        debug_print("Accepted connection on fd %d", client_fd);
        atomic_fetch_add(&active_connections, 1);

        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            perror("epoll_ctl");
            close(client_fd);
            continue;
        }

        bool connection_closed = false;
        while (!shutdown_flag && !connection_closed) {
            debug_print("Waiting for events on fd %d", client_fd);
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                perror("epoll_wait");
                break;
            }
            debug_print("epoll_wait returned %d events", nfds);
            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                debug_print("Processing event for fd %d", fd);
                ssize_t bytes_read = 0, total_read = 0;
                while (total_read < BUFFER_SIZE - 1) {
                    bytes_read = read(fd, buffer + total_read, BUFFER_SIZE - 1 - total_read);
                    if (bytes_read <= 0) break;
                    total_read += bytes_read;
                    if (buffer[total_read - 1] == '\n') break;
                }
                if (bytes_read <= 0) {
                    debug_print("Read error or EOF on fd %d", fd);
                    close(fd);
                    atomic_fetch_sub(&active_connections, 1);
                    connection_closed = true;
                    break;
                }
                buffer[total_read] = '\0';
                debug_print("Received from fd %d: '%s'", fd, buffer);

                if (strncmp(buffer, "hello\n", 6) == 0) {
                    debug_print("Received 'hello' from fd %d, sending response", fd);
                    const char *response = "hello\n";
                    write(fd, response, strlen(response));
                    debug_print("Sent response to fd %d: '%s'", fd, response);
                } else {
                    debug_print("Received unexpected message from fd %d: '%s', closing immediately", fd, buffer);
                }

                if (use_rst) {
                    struct linger sl = {1, 0};
                    setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
                    debug_print("Set SO_LINGER for RST on fd %d", fd);
                }
                close(fd);
                atomic_fetch_sub(&active_connections, 1);
                debug_print("Closed connection on fd %d", fd);
                connection_closed = true;
                break;
            }
            if (connection_closed) {
                break; // exit inner while loop
            }
        }
        // after handling connection, go back to accept
    }
    close(epoll_fd);
    debug_print("Worker thread exiting, closed epoll_fd %d", epoll_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:t:rkD")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 't': initial_threads = atoi(optarg); break;
            case 'r': use_rst = true; break;
            case 'k': drop_rst = true; break;
            case 'D': debug_mode = true; break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-t threads] [-r] [-k] [-D]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    debug_print("Starting server with port=%d, threads=%d, use_rst=%d, drop_rst=%d, debug=%d",
                port, initial_threads, use_rst, drop_rst, debug_mode);

    signal(SIGINT, handle_shutdown);
    manage_iptables(true);

    int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    pthread_t *threads = malloc(initial_threads * sizeof(pthread_t));
    for (int i = 0; i < initial_threads; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &server_fd) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec ts = {{0, 0}, {SHUTDOWN_TIMEOUT, 0}};
    while (!shutdown_flag) {
        sleep(1);
    }
    timerfd_settime(timer_fd, 0, &ts, NULL);

    uint64_t exp;
    read(timer_fd, &exp, sizeof(exp));
    while (atomic_load(&active_connections) > 0 && exp--) {
        debug_print("Waiting for %d connections to close", atomic_load(&active_connections));
        sleep(1);
    }

    for (int i = 0; i < initial_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }

    close(server_fd);
    close(timer_fd);
    free(threads);
    manage_iptables(false);
    debug_print("Server shutdown complete");
    return 0;
}
