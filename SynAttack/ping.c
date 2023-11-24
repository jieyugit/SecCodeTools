/*_______________________________________________________________*\
 *                                                               *\
 *                                                               *\
 *         Name:ping.c                                           *\
 *       Author:Liang Gang & Hu Xiao-qin                         *\
 *      Function:To demostrate how use raw socket to implement a *\
 *               simple ping                                     *\
 *          Date: 05-01-2009                                     *\
 *                                                               *\
 *                                                               *\
 *_______________________________________________________________*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>

extern int errno;

int sockfd;
struct sockaddr_in addr;
char straddr[128];
char sendbuf[2048];
char recvbuf[2048];
int sendnum;
int recvnum;
int datalen = 30;

/*compute checksum*/
unsigned short my_cksum(unsigned short *data, int len)
{
        int result = 0;
        int i;
        size_t count;

        count = strlen(data);
        for (i = 0; i < len / 2; i++)
        {
                result += *data;
                data++;
                count -= 2;
        }

        if (count > 0)
                result += *(unsigned char *)data;

        while (result >> 16)
                result = (result & 0xffff) + (result >> 16);

        return ~result;
}
/*compute the sending data time*/
void tv_sub(struct timeval *recvtime, const struct timeval *sendtime)
{
        int sec = recvtime->tv_sec - sendtime->tv_sec;
        int usec = recvtime->tv_usec - sendtime->tv_usec;
        if (usec >= 0)
        {
                recvtime->tv_sec = sec;
                recvtime->tv_usec = usec;
        }
        else
        {
                recvtime->tv_sec = sec - 1;
                recvtime->tv_usec = -usec;
        }
}
/*construct the icmp packet and send it*/
void send_icmp()
{
        struct icmp *icmp = (struct icmp *)sendbuf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = 0;
        icmp->icmp_id = getpid();   // needn't use htons() call, because peer networking kernel didn't handle this data and won't make different meanings(bigdian litteldian)
        icmp->icmp_seq = ++sendnum; // needn't use hotns() call too.
        gettimeofday((struct timeval *)icmp->icmp_data, NULL);
        int len = 8 + datalen;
        icmp->icmp_cksum = my_cksum((unsigned short *)icmp, len);
        int retval = sendto(sockfd, sendbuf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (retval == -1)
        {
                perror("sendto()");
                exit(-1);
        }
        else
        {
                printf("send icmp request to %s(%d) bytes\n", straddr, len);
        }
}

/*analysis the icmp packet and print it in screen*/

void recv_icmp()
{
        struct timeval *sendtime;
        struct timeval recvtime;
        static int index = -1;

        for (;;)
        {
                int n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, 0, 0);
                if (n == -1)
                {
                        if (errno == EINTR)
                                continue;
                        else
                        {
                                perror("recvfrom()");
                                exit(-1);
                        }
                }
                else
                {
                        gettimeofday(&recvtime, NULL);
                        struct ip *ip = (struct ip *)recvbuf;
                        if (ip->ip_src.s_addr != addr.sin_addr.s_addr)
                        {
                                // printf("ip_src is not : %s\n", straddr);
                                continue;
                        }
                        struct icmp *icmp = (struct icmp *)(recvbuf + ((ip->ip_hl) << 2));
                        if (icmp->icmp_id != getpid())
                        {
                                // printf("icmp_id is not :%d\n", getpid());
                                continue;
                        }
                        if (index == icmp->icmp_seq)
                                continue;
                        index = icmp->icmp_seq;
                        recvnum++;
                        sendtime = (struct timeval *)icmp->icmp_data;
                        tv_sub(&recvtime, sendtime);
                        printf("imcp echo from %s(%dbytes)\tttl=%d\tseq=%d\ttime=%d.%06d s\n", straddr, n, ip->ip_ttl, icmp->icmp_seq, recvtime.tv_sec, recvtime.tv_usec);
                }
        }
}
void catch_sigalrm(int signum)
{
        send_icmp();
        alarm(1);
}
void catch_sigint(int signum)
{
        printf("\nPing statics:send %d packets, recv %d packets, %d%% lost...\n", sendnum, recvnum, (int)((float)(sendnum - recvnum) / sendnum) * 100);
        exit(0);
}

int main(int argc, char **argv)
{
        if (argc != 2)
        {
                printf("please use format: ping hostname\n");
                exit(-1);
        }

        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd == -1)
        {
                perror("socket()");
                return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
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
                        inet_ntop(AF_INET, *(host->h_addr_list), straddr, sizeof(straddr));
                }
                printf("Ping address:%s(%s)\n\n", host->h_name, straddr);
        }
        else
        {
                strcpy(straddr, argv[1]);
                printf("Ping address:%s(%s)\n\n", straddr, straddr);
        }

        


        struct sigaction sa1;
        memset(&sa1, 0, sizeof(sa1));
        sa1.sa_handler = catch_sigalrm;
        sigemptyset(&sa1.sa_mask);
        sa1.sa_flags = 0;
        if (sigaction(SIGALRM, &sa1, NULL) == -1)
                perror("sigaction()");
        struct sigaction sa2;
        memset(&sa2, 0, sizeof(sa2));
        sa2.sa_handler = catch_sigint;
        sigemptyset(&sa2.sa_mask);
        sa2.sa_flags = 0;
        if (sigaction(SIGINT, &sa2, NULL) == -1)
                perror("sigaction()");

        alarm(1);
        recv_icmp();

        return 0;
}


/*
struct sigaction {
	__sighandler_t sa_handler;
	unsigned long sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;		//mask last for extensibility 
        };
*/