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
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <getopt.h>
#include <stdarg.h> // For va_start/va_end

#define DEFAULT_PORT 12345
#define MAX_WORKERS 32
#define MAX_SESSIONS 4096
#define CLIENT_TIMEOUT_SEC 2
#define MAX_RETRIES 3
#define BUF_SZ 128

// Session States
enum session_state { WAIT_HELLO, SENT_HI, WAIT_CONFIRM, FINISHED, FAILED };

typedef struct {
    struct sockaddr_in addr;
    socklen_t addrlen;
    int timer_fd;
    int retry_count;
    enum session_state state;
    bool active;
} session_t;

typedef struct {
    int udp_fd;
    int epoll_fd;
    int worker_id;
    session_t sessions[MAX_SESSIONS];
    pthread_t thread;
    unsigned long completed_sessions; // <--- Added
} worker_t;

static int port = DEFAULT_PORT;
static int num_workers = 4;
static int debug_mode = 0;
static volatile sig_atomic_t shutdown_flag = 0;

// For status thread
worker_t *global_workers = NULL;
int global_num_workers = 0;
pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;

static int session_cmp(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return (a->sin_addr.s_addr == b->sin_addr.s_addr) &&
           (a->sin_port == b->sin_port);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [-p port] [-w workers] [-D]\n", prog);
    printf("  -p <port>     UDP port to listen on (default %d)\n", DEFAULT_PORT);
    printf("  -w <workers>  Number of threads/workers (default 4, max %d)\n", MAX_WORKERS);
    printf("  -D            Enable debug output\n");
}

static void handle_sigint(int sig) {
    (void)sig;
    shutdown_flag = 1;
}

static int make_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_udp_socket(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (make_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_timerfd(int sec) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) return -1;
    struct itimerspec its;
    its.it_value.tv_sec = sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        close(tfd);
        return -1;
    }
    return tfd;
}

static void reset_timerfd(int tfd, int sec) {
    struct itimerspec its;
    its.it_value.tv_sec = sec;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    timerfd_settime(tfd, 0, &its, NULL);
}

static void debug(int wid, const char *fmt, ...) {
    if (!debug_mode) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[W%02d] ", wid);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// Find or allocate a session; returns session index or -1 if full
static int find_or_alloc_session(worker_t *w, struct sockaddr_in *from, socklen_t addrlen) {
    int free_idx = -1;
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (w->sessions[i].active &&
            session_cmp(&w->sessions[i].addr, from)) {
            return i;
        }
        if (!w->sessions[i].active && free_idx == -1) {
            free_idx = i;
        }
    }
    if (free_idx != -1) {
        // New session
        w->sessions[free_idx].addr = *from;
        w->sessions[free_idx].addrlen = addrlen;
        w->sessions[free_idx].timer_fd = -1;
        w->sessions[free_idx].retry_count = 0;
        w->sessions[free_idx].state = WAIT_HELLO;
        w->sessions[free_idx].active = true;
        return free_idx;
    }
    return -1;
}

static void close_session(worker_t *w, int idx) {
    if (!w->sessions[idx].active) return;
    if (w->sessions[idx].timer_fd != -1) {
        close(w->sessions[idx].timer_fd);
        w->sessions[idx].timer_fd = -1;
    }
    w->sessions[idx].active = false;
    w->sessions[idx].state = FINISHED;
}

static void handle_timer_event(worker_t *w, int idx) {
    // Retry if needed, or close session
    session_t *sess = &w->sessions[idx];
    if (sess->state == SENT_HI || sess->state == WAIT_CONFIRM) {
        if (sess->retry_count < MAX_RETRIES) {
            // Resend hi\n
            ssize_t s = sendto(w->udp_fd, "hi\n", 3, 0,
                (struct sockaddr*)&sess->addr, sess->addrlen);
            if (s < 0)
                debug(w->worker_id, "sendto() failed in retry: %s", strerror(errno));
            debug(w->worker_id, "Retry %d: resent hi to %s:%d",
                  sess->retry_count+1,
                  inet_ntoa(sess->addr.sin_addr),
                  ntohs(sess->addr.sin_port));
            sess->retry_count++;
            reset_timerfd(sess->timer_fd, CLIENT_TIMEOUT_SEC);
            sess->state = SENT_HI;
        } else {
            debug(w->worker_id, "Session %s:%d failed after retries",
                  inet_ntoa(sess->addr.sin_addr),
                  ntohs(sess->addr.sin_port));
            close_session(w, idx);
        }
    }
}

static void *worker_thread(void *arg) {
    worker_t *w = (worker_t*)arg;
    struct epoll_event events[1024];

    // Add UDP socket to epoll
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = w->udp_fd;
    epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->udp_fd, &ev);

    for (int i = 0; i < MAX_SESSIONS; ++i) w->sessions[i].active = false;
    w->completed_sessions = 0; // <--- Initialize

    while (!shutdown_flag) {
        int n = epoll_wait(w->epoll_fd, events, 1024, 1000);
        if (n < 0 && errno == EINTR) continue;
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == w->udp_fd) {
                // UDP event
                char buf[BUF_SZ];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                ssize_t r = recvfrom(fd, buf, sizeof(buf)-1, 0,
                                    (struct sockaddr*)&from, &fromlen);
                if (r <= 0) continue;
                buf[r] = 0;
                int idx = find_or_alloc_session(w, &from, fromlen);
                if (idx == -1) { debug(w->worker_id, "No free session slot"); continue; }
                session_t *sess = &w->sessions[idx];

                if (sess->state == WAIT_HELLO) {
                    if (strncmp(buf, "hello\n", 6) == 0) {
                        debug(w->worker_id, "Got hello from %s:%d",
                              inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                        ssize_t s = sendto(fd, "hi\n", 3, 0,
                                           (struct sockaddr*)&from, fromlen);
                        if (s < 0)
                            debug(w->worker_id, "sendto() failed: %s", strerror(errno));
                        sess->state = SENT_HI;
                        sess->retry_count = 0;
                        if (sess->timer_fd == -1) {
                            sess->timer_fd = create_timerfd(CLIENT_TIMEOUT_SEC);
                            struct epoll_event tev = {0};
                            tev.events = EPOLLIN;
                            tev.data.fd = sess->timer_fd;
                            epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, sess->timer_fd, &tev);
                        } else {
                            reset_timerfd(sess->timer_fd, CLIENT_TIMEOUT_SEC);
                        }
                    }
                } else if (sess->state == SENT_HI || sess->state == WAIT_CONFIRM) {
                    if (strncmp(buf, "got_hi\n", 7) == 0) {
                        debug(w->worker_id, "Confirmed by %s:%d, session done",
                              inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                        w->completed_sessions++; // <--- Count completed sessions
                        close_session(w, idx);
                    }
                }
            } else {
                // Timer event
                uint64_t exp;
                ssize_t rr = read(fd, &exp, sizeof(exp));
                (void)rr; // suppress unused warning
                // Find which session
                for (int j = 0; j < MAX_SESSIONS; ++j) {
                    if (w->sessions[j].active && w->sessions[j].timer_fd == fd) {
                        handle_timer_event(w, j);
                        if (!w->sessions[j].active) {
                            epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                        }
                        break;
                    }
                }
            }
        }
    }
    // Cleanup
    for (int i = 0; i < MAX_SESSIONS; ++i) close_session(w, i);
    close(w->udp_fd);
    close(w->epoll_fd);
    return NULL;
}

// Status thread: prints active and completed sessions every 5s
void *status_thread(void *arg) {
    (void)arg;
    while (!shutdown_flag) {
        sleep(5);
        int total_active = 0;
        unsigned long total_completed = 0;
        pthread_mutex_lock(&status_mutex);
        for (int i = 0; i < global_num_workers; ++i) {
            worker_t *w = &global_workers[i];
            for (int j = 0; j < MAX_SESSIONS; ++j) {
                if (w->sessions[j].active) total_active++;
            }
            total_completed += w->completed_sessions;
        }
        pthread_mutex_unlock(&status_mutex);
        printf("[STATUS] Active sessions: %d | Completed sessions: %lu\n", total_active, total_completed);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:w:Dh")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'w': num_workers = atoi(optarg); break;
            case 'D': debug_mode = 1; break;
            case 'h': default: print_usage(argv[0]); exit(0);
        }
    }
    if (num_workers < 1) num_workers = 1;
    if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;

    printf("UDP server, port %d, workers %d, debug=%d\n", port, num_workers, debug_mode);

    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    worker_t *workers = calloc(num_workers, sizeof(worker_t));
    global_workers = workers;
    global_num_workers = num_workers;

    for (int i = 0; i < num_workers; ++i) {
        workers[i].udp_fd = create_udp_socket(port);
        if (workers[i].udp_fd < 0) { perror("socket"); exit(1); }
        workers[i].epoll_fd = epoll_create1(0);
        if (workers[i].epoll_fd < 0) { perror("epoll"); exit(1); }
        workers[i].worker_id = i;
        workers[i].completed_sessions = 0;
        pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]);
    }

    pthread_t stid;
    pthread_create(&stid, NULL, status_thread, NULL);

    for (int i = 0; i < num_workers; ++i) {
        pthread_join(workers[i].thread, NULL);
    }
    shutdown_flag = 1;

    pthread_join(stid, NULL);

    printf("Server shutting down.\n");
    free(workers);
    return 0;
}
