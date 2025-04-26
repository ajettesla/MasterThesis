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

#define DEFAULT_BACKLOG    1024
#define MAX_EVENTS         1024
#define MIN_THREADS        1
#define MAX_THREADS        16
#define CHECK_INTERVAL     1   // seconds

// Scaling thresholds
#define UP_CONN            15000  // if avg connections per thread > this, scale up
#define DOWN_CONN          1000   // if avg connections per thread < this, scale down
#define UP_Q               20     // if avg backlog batch > this, scale up
#define DOWN_Q             5      // if avg backlog batch < this, scale down

volatile int current_threads = 0;
int pipe_writes[MAX_THREADS];
pthread_t threads[MAX_THREADS];
int g_port = 0;

atomic_int established_count = 0;
atomic_int fin_count = 0;
atomic_int global_batch_sum = 0;
atomic_int global_batch_count = 0;

struct worker_arg {
    int port;
    int pipe_read;
};

// Forward declaration of worker thread entry
void *worker(void *arg);

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) { perror("fcntl get"); return; }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) { perror("fcntl set"); }
}

ssize_t read_n(int fd, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            if (n == 0) return total;
            return -1;
        }
        total += n;
    }
    return total;
}

ssize_t write_n(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) return -1;
        total += n;
    }
    return total;
}

// Spawn a new worker thread
void spawn_worker(int thread_id) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return;
    }
    struct worker_arg *wa = malloc(sizeof(*wa));
    wa->port = g_port;
    wa->pipe_read = pipefd[0];
    pipe_writes[thread_id] = pipefd[1];

    if (pthread_create(&threads[thread_id], NULL, worker, wa) != 0) {
        perror("pthread_create");
        free(wa);
        close(pipefd[0]); close(pipefd[1]);
        return;
    }
    pthread_detach(threads[thread_id]);
}

void *worker(void *arg) {
    struct worker_arg *wa = arg;
    int port = wa->port;
    int pipe_read = wa->pipe_read;
    free(wa);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return NULL; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(listen_fd);

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("bind"); close(listen_fd); return NULL;
    }
    if (listen(listen_fd, DEFAULT_BACKLOG) < 0) {
        perror("listen"); close(listen_fd); return NULL;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(listen_fd); return NULL; }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    ev.data.fd = pipe_read;
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_read, &ev);

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == pipe_read) {
                char buf;
                if (read(pipe_read, &buf, 1) > 0 && buf == 'q') goto cleanup;
            } else if (fd == listen_fd) {
                int batch = 0;
                while (1) {
                    int client_fd = accept(listen_fd, NULL, NULL);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept"); continue;
                    }
                    batch++;
                    set_nonblocking(client_fd);
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = client_fd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
                        perror("epoll_ctl client"); close(client_fd);
                    } else {
                        atomic_fetch_add(&established_count, 1);
                    }
                }
                atomic_fetch_add(&global_batch_sum, batch);
                atomic_fetch_add(&global_batch_count, 1);
            } else {
                char buf[20];
                ssize_t r = read_n(fd, buf, 19);
                if (r == 19) write_n(fd, "hello this is server", 19);
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

void *scaler(void *_) {
    int prev_sum = 0, prev_cnt = 0;
    while (1) {
        sleep(CHECK_INTERVAL);
        int sum = atomic_load(&global_batch_sum) - prev_sum;
        int cnt = atomic_load(&global_batch_count) - prev_cnt;
        prev_sum += sum;
        prev_cnt += cnt;
        double avg_batch = cnt ? (double)sum / cnt : 0;
        int tot_conn = atomic_load(&established_count);
        double avg_conn = current_threads ? (double)tot_conn / current_threads : 0;

        if ((avg_batch > UP_Q || avg_conn > UP_CONN) && current_threads < MAX_THREADS) {
            spawn_worker(current_threads);
            current_threads++;
            printf("[Scaler] UP → threads=%d, avg_batch=%.2f, avg_conn=%.2f\n",
                   current_threads, avg_batch, avg_conn);
        } else if ((avg_batch < DOWN_Q && avg_conn < DOWN_CONN) && current_threads > MIN_THREADS) {
            int id = current_threads - 1;
            write(pipe_writes[id], "q", 1);
            current_threads--;
            printf("[Scaler] DOWN → threads=%d, avg_batch=%.2f, avg_conn=%.2f\n",
                   current_threads, avg_batch, avg_conn);
        }
        fflush(stdout);
    }
    return NULL;
}

void *print_connection_stats(void *_) {
    time_t start = time(NULL);
    while (1) {
        sleep(1);
        time_t elapsed = time(NULL) - start;
        printf("Time: %lds | EST: %d | FIN: %d\n",
               elapsed,
               atomic_load(&established_count),
               atomic_load(&fin_count));
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p': g_port = atoi(optarg); break;
            default:
                fprintf(stderr, "Usage: %s -p <port>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!g_port) {
        fprintf(stderr, "Port is required\n");
        exit(EXIT_FAILURE);
    }

    struct rlimit rl = {100000, 100000};
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) perror("setrlimit");

    printf("Server starting on port %d\n", g_port);

    current_threads = MIN_THREADS;
    for (int i = 0; i < MIN_THREADS; i++) {
        spawn_worker(i);
    }

    pthread_t scaler_thread, stats_thread;
    pthread_create(&scaler_thread, NULL, scaler, NULL);
    pthread_create(&stats_thread, NULL, print_connection_stats, NULL);

    while (1) sleep(CHECK_INTERVAL);
    return 0;
}
