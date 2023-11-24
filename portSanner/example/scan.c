#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port_range>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *hostname = argv[1];
    char *port_range = argv[2];
    
    struct hostent *host;
    host = gethostbyname(hostname);

    if (host == NULL) {
        perror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    int sockfd;
    struct sockaddr_in target;
    struct servent *service_info;
    char *name;
    
    int start_port, end_port;
    sscanf(port_range, "%d-%d", &start_port, &end_port);

    for (int port = start_port; port <= end_port; ++port) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfd == -1) {
            perror("socket");
            continue;
        }

        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        memcpy(&target.sin_addr, host->h_addr, host->h_length);

        if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == 0) {
            service_info = getservbyport(htons(port), "tcp");
            if (service_info == NULL) {
                perror("getservbyport");
                return 1;
            }
            name = service_info->s_name == NULL ? "unknown" : service_info->s_name;
            printf("Port %d is open. Service name is %s\n",port,name);
            close(sockfd);
        }
    }

    return 0;
}
