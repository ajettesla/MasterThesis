#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_MESSAGE_LEN 1024
#define SYSLOG_PORT 514 // Default syslog port

// Function to generate a simple syslog message (RFC 5424 format)
void create_syslog_message(char *buffer, const char *message, const char *hostname, const char *app_name) {
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    char timestamp[64];
    
    // Format timestamp as ISO 8601
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);
    
    // Construct syslog message
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    snprintf(buffer, MAX_MESSAGE_LEN, "<134>1 %s %s %s - - - %s\n",
             timestamp, hostname, app_name, message);
}

// Function to send syslog message to the server over TCP
int send_syslog_message(const char *server_ip, int port, const char *message) {
    int sockfd;
    struct sockaddr_in server_addr;
    char syslog_msg[MAX_MESSAGE_LEN];
    
    // Create TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sockfd);
        return -1;
    }
    
    // Connect to the syslog server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to syslog server failed");
        close(sockfd);
        return -1;
    }
    
    // Create syslog message
    create_syslog_message(syslog_msg, message, "localhost", "testapp");
    
    // Send message to syslog server
    if (send(sockfd, syslog_msg, strlen(syslog_msg), 0) < 0) {
        perror("Failed to send syslog message");
        close(sockfd);
        return -1;
    }
    
    printf("Syslog message sent: %s", syslog_msg);
    close(sockfd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <syslog_server_ip> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    const char *server_ip = argv[1];
    const char *message = argv[2];
    
    if (send_syslog_message(server_ip, SYSLOG_PORT, message) < 0) {
        fprintf(stderr, "Failed to send syslog message\n");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}
