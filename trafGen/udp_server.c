#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>

#define DEFAULT_BACKLOG 1024
#define MAX_EVENTS 1024
#define MIN_THREADS 1
#define MAX_THREADS 16
#define CHECK_INTERVAL 1

volatile int current_threads = 0;
int pipe_writes[MAX_THREADS];
pthread_t threads[MAX_THREADS];

struct worker_arg {
    int port;
    int thread_id;
    int pipe_read;
};

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) { perror("fcntl get"); return; }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) { perror("fcntl set"); }
}

void *worker(void *arg) {
    struct worker_arg *wa = arg;
    int port = wa->port;
    int thread_id = wa->thread_id;
    int pipe_read = wa->pipe_read;
    free(wa);

    // Create UDP socket
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) { perror("socket"); return NULL; }

    // Set socket options
    int flags = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(flags));

    set_nonblocking(sock_fd);

    // Bind socket to address
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("bind");
        close(sock_fd);
        return NULL;
    }

    // Set up epoll
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(sock_fd); return NULL; }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock_fd, &ev) < 0) {
        perror("epoll_ctl sock");
        close(epfd);
        close(sock_fd);
        return NULL;
    }

    ev.events = EPOLLIN;
    ev.data.fd = pipe_read;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_read, &ev) < 0) {
        perror("epoll_ctl pipe");
        close(epfd);
        close(sock_fd);
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == pipe_read) {
                char buf;
                if (read(pipe_read, &buf, 1) > 0 && buf == 'q') {
                    goto cleanup;
                }
            } else if (events[i].data.fd == sock_fd) {
                char buf[20];
                struct sockaddr_storage from;
                socklen_t fromlen = sizeof(from);

                // Receive datagram from client
                ssize_t n = recvfrom(sock_fd, buf, 19, 0, (struct sockaddr *)&from, &fromlen);
                if (n == 19) {
                    const char *response = "hello this is server";
                    // Send response back to client
                    if (sendto(sock_fd, response, 19, 0, (struct sockaddr *)&from, fromlen) != 19) {
                        perror("sendto");
                    }
                } else if (n < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom");
                    }
                } else {
                    printf("Short receive: %zd bytes\n", n);
                }
            }
        }
    }

cleanup:
    close(epfd);
    close(sock_fd);
    close(pipe_read);
    return NULL;
}

void *print_connection_stats(void *arg) {
    time_t start_time = time(NULL);
    while (1) {
        sleep(1);
        time_t elapsed_time = time(NULL) - start_time;
        printf("Execution Time: %ld seconds\n", elapsed_time);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt, port = 0;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        default:
            fprintf(stderr, "Usage: %s -p <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (!port) {
        fprintf(stderr, "Port is required\n");
        exit(EXIT_FAILURE);
    }

    // Set file descriptor limit
    struct rlimit rl;
    rl.rlim_cur = 100000;
    rl.rlim_max = 100000;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
        perror("setrlimit");
    }

    printf("Server starting on port %d\n", port);

    current_threads = MIN_THREADS;
    for (int i = 0; i < MIN_THREADS; i++) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("pipe");
            continue;
        }
        struct worker_arg *wa = malloc(sizeof(*wa));
        wa->port = port;
        wa->thread_id = i;
        wa->pipe_read = pipefd[0];
        pipe_writes[i] = pipefd[1];
        if (pthread_create(&threads[i], NULL, worker, wa) != 0) {
            perror("pthread_create");
            free(wa);
            close(pipefd[0]);
            close(pipefd[1]);
        } else {
            pthread_detach(threads[i]);
        }
    }

    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, print_connection_stats, NULL);

    while (1) {
        sleep(CHECK_INTERVAL);
    }
    return 0;
}
