#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <sys/timerfd.h>
#include <time.h>

#define MAX_EVENTS 64
#define LISTEN_BACKLOG 128
#define MAX_CONNECTIONS 1024

int rule_added = 0;
volatile sig_atomic_t quit = 0;
struct connection *connections[MAX_CONNECTIONS] = {0};

struct connection {
    int sock_fd;
    int timer_fd;
    bool hello_received;
};

void signal_handler(int signum) {
    quit = 1;
    fprintf(stderr, "Terminating due to Ctrl-C\n");
}

void cleanup_connection(struct connection *conn, int epoll_fd) {
    if (conn->sock_fd != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->sock_fd, NULL);
        struct linger sl = {1, 0}; // Force RST on close
        setsockopt(conn->sock_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        close(conn->sock_fd);
    }
    if (conn->timer_fd != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->timer_fd, NULL);
        close(conn->timer_fd);
    }
    free(conn);
}

void cleanup_all_connections(int epoll_fd) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i]) {
            cleanup_connection(connections[i], epoll_fd);
            connections[i] = NULL;
        }
    }
}

int find_free_slot() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i] == NULL) return i;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    int opt, port = 5000, wait_ms = 0;
    bool kill_flag = false;

    while ((opt = getopt(argc, argv, "p:w:k")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'w': wait_ms = atoi(optarg); break;
            case 'k': kill_flag = true; break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-w wait_ms] [-k]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (kill_flag) {
        system("iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP");
        rule_added = 1;
    }

    struct sigaction sa = {.sa_handler = signal_handler, .sa_flags = SA_RESTART};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 ||
        listen(listen_fd, LISTEN_BACKLOG) < 0) {
        perror("bind/listen"); close(listen_fd); exit(EXIT_FAILURE);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); close(listen_fd); exit(EXIT_FAILURE); }

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = listen_fd};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

    printf("Server listening on port %d\n", port);

    while (true) {
        struct epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_fd) {
                if (quit) continue; // Stop accepting new connections on Ctrl-C
                struct sockaddr_in cli_addr;
                socklen_t addrlen = sizeof(cli_addr);
                int conn_fd = accept(listen_fd, (struct sockaddr*)&cli_addr, &addrlen);
                if (conn_fd < 0) { perror("accept"); continue; }

                int slot = find_free_slot();
                if (slot == -1) { close(conn_fd); continue; }

                struct connection *conn = malloc(sizeof(*conn));
                conn->sock_fd = conn_fd;
                conn->timer_fd = -1;
                conn->hello_received = false;

                fcntl(conn_fd, F_SETFL, O_NONBLOCK);
                ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
                ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);

                send(conn_fd, "hello", strlen("hello"), 0);
                connections[slot] = conn;
            } else {
                struct connection *conn = events[i].data.ptr;
                if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                    for (int j = 0; j < MAX_CONNECTIONS; j++) {
                        if (connections[j] == conn) {
                            cleanup_connection(conn, epoll_fd);
                            connections[j] = NULL;
                            break;
                        }
                    }
                } else if (events[i].events & EPOLLIN) {
                    if (conn->timer_fd == -1) {
                        char buffer[1024];
                        ssize_t count = recv(conn->sock_fd, buffer, sizeof(buffer), 0);
                        if (count <= 0) {
                            for (int j = 0; j < MAX_CONNECTIONS; j++) {
                                if (connections[j] == conn) {
                                    cleanup_connection(conn, epoll_fd);
                                    connections[j] = NULL;
                                    break;
                                }
                            }
                        } else if (!conn->hello_received && strncmp(buffer, "hello", 5) == 0) {
                            conn->hello_received = true;
                            if (wait_ms > 0) {
                                int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
                                struct itimerspec its = {
                                    .it_value.tv_sec = wait_ms / 1000,
                                    .it_value.tv_nsec = (wait_ms % 1000) * 1000000
                                };
                                timerfd_settime(timer_fd, 0, &its, NULL);
                                conn->timer_fd = timer_fd;
                                ev.events = EPOLLIN;
                                ev.data.ptr = conn;
                                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);
                            } else {
                                for (int j = 0; j < MAX_CONNECTIONS; j++) {
                                    if (connections[j] == conn) {
                                        cleanup_connection(conn, epoll_fd);
                                        connections[j] = NULL;
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        uint64_t exp;
                        read(conn->timer_fd, &exp, sizeof(exp));
                        for (int j = 0; j < MAX_CONNECTIONS; j++) {
                            if (connections[j] == conn) {
                                cleanup_connection(conn, epoll_fd);
                                connections[j] = NULL;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (quit) {
            bool active_connections = false;
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (connections[i]) {
                    active_connections = true;
                    break;
                }
            }
            if (!active_connections) break; // Exit when all connections are done
        }
    }

    cleanup_all_connections(epoll_fd);
    if (rule_added) system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");
    close(listen_fd);
    close(epoll_fd);
    printf("Server shut down gracefully.\n");
    return 0;
}
