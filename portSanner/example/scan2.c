#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

int main(int argc, char *argv[]) {
    // if (argc != 4) {
    //     fprintf(stderr, "Usage: %s <IP_address> <start_port> <end_port>\n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    // char *ip_address = argv[1];
    // int start_port = atoi(argv[2]);
    // int end_port = atoi(argv[3]);
    printf("***************************************");
    char *ip_address = "192.168.0.1";
    int start_port = 1;
    int end_port = 100;

    int sockfd;
    struct sockaddr_in target;
    struct servent *service_info;
    char *name;
    printf("***************************************");
    for (int port = start_port; port <= end_port; ++port) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfd == -1) {
            perror("socket");
            continue;
        }
        printf("**********************");
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, ip_address, &(target.sin_addr));

        if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == 0) {
            service_info = getservbyport(htons(port), "tcp");
            if (service_info == NULL) {
                perror("getservbyport");
                return 1;
            }
            name = service_info->s_name == NULL ? "unknown" :service_info->s_name;
            printf("Port %d is open. Service name is %s\n",port,name);
            close(sockfd);
        }
    }

    return 0;
}
