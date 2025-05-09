/* client.c - TCP client with optional -k flag for RST termination and cleanup */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

int g_kill_flag = 0;
int rule_added = 0;

typedef struct {
    char host[256];
    int port;
} client_arg_t;

void *client_thread(void *arg) {
    client_arg_t *carg = (client_arg_t*)arg;
    int sockfd;
    struct sockaddr_in serv_addr;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        free(carg);
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(carg->port);

    /* Convert hostname/IP */
    if (inet_pton(AF_INET, carg->host, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", carg->host);
        close(sockfd);
        free(carg);
        return NULL;
    }

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        free(carg);
        return NULL;
    }

    printf("Connected to %s:%d\n", carg->host, carg->port);

    /* Example send/receive (can be adjusted as needed) */
    const char *msg = "Hello";
    send(sockfd, msg, strlen(msg), 0);

    char buffer[1024];
    ssize_t count = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (count > 0) {
        buffer[count] = '\0';
        printf("Received from %s:%d: %s\n", carg->host, carg->port, buffer);
    }

    /* Before closing, if -k flag is used, set SO_LINGER to 0 to force RST */
    if (g_kill_flag) {
        struct linger lin = {1, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
    }

    close(sockfd);
    free(carg);
    return NULL;
}

int main(int argc, char *argv[]) {
    int opt;

    /* Parse command-line options */
    while ((opt = getopt(argc, argv, "k")) != -1) {
        switch (opt) {
        case 'k':
            g_kill_flag = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-k] host1 port1 [host2 port2 ...]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    /* Remaining args are host port pairs */
    int remaining = argc - optind;
    if (remaining <= 0 || (remaining % 2) != 0) {
        fprintf(stderr, "Expected host port pairs\n");
        exit(EXIT_FAILURE);
    }
    int num_threads = remaining / 2;

    /* If -k is set, insert iptables rule to drop outgoing RST packets */
    if (g_kill_flag) {
        system("iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP");
        rule_added = 1;
    }

    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        client_arg_t *carg = malloc(sizeof(*carg));
        strncpy(carg->host, argv[optind + 2*i], sizeof(carg->host) - 1);
        carg->host[sizeof(carg->host) - 1] = '\0';
        carg->port = atoi(argv[optind + 2*i + 1]);

        if (pthread_create(&threads[i], NULL, client_thread, carg) != 0) {
            perror("pthread_create");
            free(carg);
        }
    }

    /* Wait for all threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Cleanup */
    if (rule_added) {
        system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");
    }

    return 0;
}
