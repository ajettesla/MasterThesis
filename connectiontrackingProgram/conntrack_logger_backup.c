#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <openssl/sha.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <stdatomic.h>

#define PIPE_BUFFER_SIZE 1024
#define MAX_MESSAGE_LEN 2048
#define SYSLOG_PORT "514"
#define MIN_BATCH_SIZE 5

struct config {
    char *syslog_ip;
    char *machine_name;
    int daemonize;
    int kill_daemons;
    int count_enabled;
};

struct conn_event {
    long long count;
    long long timestamp_ns;
    char hash[65];
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port;
    char protocol_str[16];
    const char *msg_type_str;
    uint32_t timeout;
    const char *state_str;
    const char *assured_str;
};

struct callback_data {
    int pipe_fd;
    int print_to_stdout;
    int count_enabled;
};

struct syslog_data {
    int pipe_fd;
    char *syslog_ip;
    int syslog_fd;
    char *machine_name;
    int count_enabled;
    pthread_mutex_t mutex;
};

static atomic_llong event_counter = 0;

static void print_help(const char *progname) {
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -n, --machine-name <name> Specify machine name (required)\n");
    printf("  -l, --sip <address>       Specify syslog server IP/domain (required)\n");
    printf("  -d, --daemonize           Daemonize the program (optional)\n");
    printf("  -k, --kill                Kill all running daemons (optional)\n");
    printf("  -c, --count <yes|no>      Prepend query/event count to each event (optional)\n");
}

static int parse_config(int argc, char *argv[], struct config *cfg) {
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"machine-name", required_argument, 0, 'n'},
        {"sip", required_argument, 0, 'l'},
        {"daemonize", no_argument, 0, 'd'},
        {"kill", no_argument, 0, 'k'},
        {"count", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    int opt;
    cfg->syslog_ip = NULL;
    cfg->machine_name = NULL;
    cfg->daemonize = 0;
    cfg->kill_daemons = 0;
    cfg->count_enabled = 0;

    while ((opt = getopt_long(argc, argv, "hn:l:dkc:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_help(argv[0]); exit(0);
            case 'n': cfg->machine_name = optarg; break;
            case 'l': cfg->syslog_ip = optarg; break;
            case 'd': cfg->daemonize = 1; break;
            case 'k': cfg->kill_daemons = 1; break;
            case 'c':
                if (strcasecmp(optarg, "yes") == 0)
                    cfg->count_enabled = 1;
                else
                    cfg->count_enabled = 0;
                break;
            default: print_help(argv[0]); return 1;
        }
    }

    if (!cfg->kill_daemons && (!cfg->syslog_ip || !cfg->machine_name)) {
        fprintf(stderr, "Syslog server IP/domain and machine name are required\n");
        print_help(argv[0]);
        return 1;
    }
    return 0;
}

static void calculate_sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

static void extract_conn_event(struct nf_conntrack *ct, enum nf_conntrack_msg_type type, struct conn_event *event, int count_enabled) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    event->timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;

    if (count_enabled) {
        event->count = atomic_fetch_add(&event_counter, 1) + 1;
    } else {
        event->count = 0;
    }

    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    inet_ntop(AF_INET, &src_addr, event->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, event->dst_ip, INET_ADDRSTRLEN);

    event->src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    event->dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    if (proto == IPPROTO_TCP) strcpy(event->protocol_str, "tcp");
    else if (proto == IPPROTO_UDP) strcpy(event->protocol_str, "udp");
    else snprintf(event->protocol_str, sizeof(event->protocol_str), "proto %u", proto);

    char hash_input[256];
    snprintf(hash_input, sizeof(hash_input), "%s%s%u%u%s", event->src_ip, event->dst_ip, event->src_port, event->dst_port, event->protocol_str);
    calculate_sha256(hash_input, event->hash);

    switch (type) {
        case NFCT_T_NEW:     event->msg_type_str = "NEW";     break;
        case NFCT_T_UPDATE:  event->msg_type_str = "UPDATE";  break;
        case NFCT_T_DESTROY: event->msg_type_str = "DESTROY"; break;
        default:             event->msg_type_str = "UNKNOWN"; break;
    }

    event->timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;

    event->state_str = "N/A";
    if (proto == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        uint8_t tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        switch (tcp_state) {
            case 0: event->state_str = "NONE"; break;
            case 1: event->state_str = "SYN_SENT"; break;
            case 2: event->state_str = "SYN_RECV"; break;
            case 3: event->state_str = "ESTABLISHED"; break;
            case 4: event->state_str = "FIN_WAIT"; break;
            case 5: event->state_str = "CLOSE_WAIT"; break;
            case 6: event->state_str = "LAST_ACK"; break;
            case 7: event->state_str = "TIME_WAIT"; break;
            case 8: event->state_str = "CLOSE"; break;
            default: event->state_str = "UNKNOWN"; break;
        }
    }

    event->assured_str = "N/A";
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) event->assured_str = "ASSURED";
    }
}

static int event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    struct callback_data *cb_data = (struct callback_data *)data;
    struct conn_event event = {0};
    extract_conn_event(ct, type, &event, cb_data->count_enabled);

    char buffer[PIPE_BUFFER_SIZE];
    if (cb_data->count_enabled) {
        snprintf(buffer, sizeof(buffer),
            "%lld,%lld,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
            event.count, event.timestamp_ns, event.hash,
            event.src_ip, event.src_port, event.dst_ip, event.dst_port,
            event.protocol_str, event.msg_type_str, event.timeout,
            event.state_str, event.assured_str);
    } else {
        snprintf(buffer, sizeof(buffer),
            "%lld,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
            event.timestamp_ns, event.hash,
            event.src_ip, event.src_port, event.dst_ip, event.dst_port,
            event.protocol_str, event.msg_type_str, event.timeout,
            event.state_str, event.assured_str);
    }

    if (write(cb_data->pipe_fd, buffer, strlen(buffer) + 1) < 0) {
        perror("Failed to write to pipe");
    }

    if (cb_data->print_to_stdout) {
        printf("%s", buffer);
    }

    return NFCT_CB_CONTINUE;
}

// Uses getaddrinfo to resolve both IP addresses and hostnames (including localhost)
static int connect_to_syslog(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int sock = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo failed for %s:%s: %s\n", host, port, gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock == -1) {
        fprintf(stderr, "Failed to connect to syslog server at %s:%s\n", host, port);
    }
    return sock;
}

static void create_syslog_message(char *msg, size_t len, const char *timestamp, const char *data) {
    snprintf(msg, len, "<134>1 %s localhost conntrack_logger - - - %s", timestamp, data);
}

static void *syslog_thread(void *arg) {
    struct syslog_data *sdata = (struct syslog_data *)arg;
    char buffer[PIPE_BUFFER_SIZE];
    char batch[MAX_MESSAGE_LEN * MIN_BATCH_SIZE] = "";
    int message_count = 0;

    while (1) {
        ssize_t n = read(sdata->pipe_fd, buffer, sizeof(buffer));
        if (n <= 0) {
            if (n < 0) perror("Failed to read from pipe");
            continue;
        }

        struct conn_event event;
        char msg_type_str[16], state_str[16], assured_str[16];
        if (sdata->count_enabled) {
            sscanf(buffer, "%lld,%lld,%64[^,],%15[^,],%hu,%15[^,],%hu,%15[^,],%15[^,],%u,%15[^,],%15[^,]",
                   &event.count, &event.timestamp_ns, event.hash,
                   event.src_ip, &event.src_port, event.dst_ip, &event.dst_port,
                   event.protocol_str, msg_type_str, &event.timeout,
                   state_str, assured_str);
        } else {
            sscanf(buffer, "%lld,%64[^,],%15[^,],%hu,%15[^,],%hu,%15[^,],%15[^,],%u,%15[^,],%15[^,]",
                   &event.timestamp_ns, event.hash,
                   event.src_ip, &event.src_port, event.dst_ip, &event.dst_port,
                   event.protocol_str, msg_type_str, &event.timeout,
                   state_str, assured_str);
            event.count = 0;
        }
        event.msg_type_str = msg_type_str;
        event.state_str = state_str;
        event.assured_str = assured_str;

        char message[512];
        if (sdata->count_enabled) {
            snprintf(message, sizeof(message),
                     "connection_tracking %s %lld,%lld,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s",
                     sdata->machine_name, event.count, event.timestamp_ns, event.hash,
                     event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                     event.protocol_str, event.msg_type_str, event.timeout,
                     event.state_str, event.assured_str);
        } else {
            snprintf(message, sizeof(message),
                     "connection_tracking %s %lld,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s",
                     sdata->machine_name, event.timestamp_ns, event.hash,
                     event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                     event.protocol_str, event.msg_type_str, event.timeout,
                     event.state_str, event.assured_str);
        }

        strncat(batch, message, sizeof(batch) - strlen(batch) - 1);
        strncat(batch, "; ", sizeof(batch) - strlen(batch) - 1);
        message_count++;

        if (message_count >= MIN_BATCH_SIZE) {
            pthread_mutex_lock(&sdata->mutex);
            if (sdata->syslog_fd < 0) {
                sdata->syslog_fd = connect_to_syslog(sdata->syslog_ip, SYSLOG_PORT);
                if (sdata->syslog_fd < 0) perror("Syslog reconnection failed");
            }
            if (sdata->syslog_fd >= 0) {
                char syslog_msg[MAX_MESSAGE_LEN * MIN_BATCH_SIZE];
                time_t now = time(NULL);
                struct tm *tm = gmtime(&now);
                char timestamp[64];
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);
                create_syslog_message(syslog_msg, sizeof(syslog_msg), timestamp, batch);
                if (send(sdata->syslog_fd, syslog_msg, strlen(syslog_msg), 0) < 0) {
                    perror("Failed to send to syslog");
                    close(sdata->syslog_fd);
                    sdata->syslog_fd = -1;
                }
            }
            pthread_mutex_unlock(&sdata->mutex);

            batch[0] = '\0';
            message_count = 0;
        }
    }
    return NULL;
}

static void kill_all_daemons() {
    pid_t current_pid = getpid();
    FILE *fp = popen("pidof conntrack_logger", "r");
    if (!fp) {
        perror("Failed to run pidof");
        return;
    }
    char pid_str[16];
    while (fscanf(fp, "%s", pid_str) == 1) {
        pid_t pid = atoi(pid_str);
        if (pid != current_pid) {
            if (kill(pid, SIGTERM) == -1) {
                perror("Failed to kill process");
            }
        }
    }
    pclose(fp);
}

int main(int argc, char *argv[]) {
    struct config cfg;
    if (parse_config(argc, argv, &cfg)) return 1;

    if (cfg.kill_daemons) {
        kill_all_daemons();
        printf("Killed all running daemons\n");
        return 0;
    }

    if (getuid() != 0) {
        fprintf(stderr, "This program requires root privileges. Please run with sudo.\n");
        return 1;
    }

    int syslog_fd = connect_to_syslog(cfg.syslog_ip, SYSLOG_PORT);
    if (syslog_fd < 0) {
        fprintf(stderr, "Failed to connect to syslog server at %s:%s\n", cfg.syslog_ip, SYSLOG_PORT);
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("Pipe creation failed");
        close(syslog_fd);
        return 1;
    }

    struct syslog_data sdata = {pipefd[0], cfg.syslog_ip, syslog_fd, cfg.machine_name, cfg.count_enabled, PTHREAD_MUTEX_INITIALIZER};
    pthread_t syslog_tid;
    if (pthread_create(&syslog_tid, NULL, syslog_thread, &sdata) != 0) {
        perror("Failed to create syslog thread");
        close(pipefd[0]);
        close(pipefd[1]);
        close(syslog_fd);
        return 1;
    }
    pthread_detach(syslog_tid);

    if (cfg.daemonize) {
        if (daemon(0, 0) < 0) {
            perror("Failed to daemonize");
            close(pipefd[0]);
            close(pipefd[1]);
            close(syslog_fd);
            return 1;
        }
    }

    struct callback_data cb_data = {pipefd[1], !cfg.daemonize, cfg.count_enabled};
    struct nfct_handle *cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                        NF_NETLINK_CONNTRACK_UPDATE |
                                        NF_NETLINK_CONNTRACK_DESTROY);
    if (!cth) {
        perror("Failed to open conntrack handle");
        close(pipefd[0]);
        close(pipefd[1]);
        close(syslog_fd);
        return 1;
    }

    nfct_callback_register(cth, NFCT_T_ALL, event_cb, &cb_data);
    if (nfct_catch(cth) < 0) {
        perror("Failed to catch conntrack events");
    }

    nfct_close(cth);
    close(pipefd[0]);
    close(pipefd[1]);
    close(syslog_fd);
    pthread_mutex_destroy(&sdata.mutex);
    return 0;
}

