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
#include <stdatomic.h>

#define DEFAULT_BACKLOG 1024
#define MAX_EVENTS 1024
#define MIN_THREADS 1
#define MAX_THREADS 16
#define CHECK_INTERVAL 1

volatile int current_threads = 0;
int pipe_writes[MAX_THREADS];
int connections_accepted[MAX_THREADS];
int previous_connections[MAX_THREADS];
pthread_t threads[MAX_THREADS];

atomic_int established_count = 0;
atomic_int fin_count = 0;

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

// Helper function to read exactly len bytes
ssize_t read_n(int fd, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            if (n == 0) return total; // EOF
            else return -1; // error
        }
        total += n;
    }
    return total;
}

// Helper function to write exactly len bytes
ssize_t write_n(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) return -1;
        total += n;
    }
    return total;
}

void *worker(void *arg) {
    struct worker_arg *wa = arg;
    int port = wa->port;
    int thread_id = wa->thread_id;
    int pipe_read = wa->pipe_read;
    free(wa);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return NULL; }

    int flags = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(flags));

    set_nonblocking(listen_fd);

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("bind");
        close(listen_fd);
        return NULL;
    }
    if (listen(listen_fd, DEFAULT_BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return NULL;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(listen_fd); return NULL; }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("epoll_ctl listen");
        close(epfd);
        close(listen_fd);
        return NULL;
    }

    ev.events = EPOLLIN;
    ev.data.fd = pipe_read;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_read, &ev) < 0) {
        perror("epoll_ctl pipe");
        close(epfd);
        close(listen_fd);
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
            } else if (events[i].data.fd == listen_fd) {
                while (1) {
                    int client_fd = accept(listen_fd, NULL, NULL);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept");
                        continue;
                    }
                    __sync_fetch_and_add(&connections_accepted[thread_id], 1);
                    set_nonblocking(client_fd);
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = client_fd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
                        perror("epoll_ctl client");
                        close(client_fd);
                    } else {
                        atomic_fetch_add(&established_count, 1);
                    }
                }
            } else {
                int fd = events[i].data.fd;
                char buf[20];
                ssize_t n = read_n(fd, buf, 19);
                if (n == 19) {
                    const char *response = "hello this is server";
                    if (write_n(fd, response, 19) < 0) {
                        perror("write");
                    }
                } else if (n < 0) {
                    perror("read");
                } else {
                    printf("Short read: %zd bytes\n", n);
                }
                close(fd);
                atomic_fetch_sub(&established_count, 1);
                atomic_fetch_add(&fin_count, 1);
            }
        }
    }
cleanup:
    close(epfd);
    close(listen_fd);
    close(pipe_read);
    return NULL;
}

void *print_connection_stats(void *arg) {
    time_t start_time = time(NULL);
    while (1) {
        sleep(1);
        time_t elapsed_time = time(NULL) - start_time;
        printf("Execution Time: %ld seconds\n", elapsed_time);
        printf("Connection States: ESTABLISHED: %d, FIN_WAIT: %d\n",
               atomic_load(&established_count), atomic_load(&fin_count));
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
