#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#define MAX_SIZE 1024
#define PORT 8088
#define IP "127.0.0.1"

void scan(char *ip, int start_port, int end_port)
{
    int clientSocket;
    struct sockaddr_in serverAddr;
    struct servent *service_info;
    char *name;

    for (int port = start_port; port <= end_port; ++port)
    {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);

        if (clientSocket < 0)
        {
            perror("Error in socket");
            exit(1);
        }

        // 设置服务器地址结构
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr.s_addr = inet_addr(ip);

        // 连接到服务器
        if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0)
        {
            service_info = getservbyport(htons(port), "tcp");
            if (service_info == NULL)
            {
                printf("Port %d is open. Service name is unknown\n", port);
            }
            else
            {
                name = service_info->s_name == NULL ? "unknown" : service_info->s_name;
                printf("Port %d is open. Service name is %s\n", port, name);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <ip_addr> <port_range>\n", argv[0]);
        printf("Default:\nIP: 127.0.0.1\nPORT: 1-10000\n");
        scan("127.0.0.1", 1, 10000);
    }
    else
    {
        char *ip = argv[1];
        char *port_range = argv[2];
        int start_port, end_port;
        sscanf(port_range, "%d-%d", &start_port, &end_port);
        scan(ip, start_port, end_port);
    }

    return 0;
}