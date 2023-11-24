#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

static long int packet_num = 0;

void print(u_char *payload, int len, int offset, int maxlen, int width, int last)
{
    printf("%.5d  ", offset); // 打印偏移量(宽度为5)
    int max = maxlen;         // 数据包的有效载荷和长度
    int i;
    for (i = 0; i < width; i++) // 打印16个字节的16进制payload
    {
        if (i == 8)
        {
            printf("  ");
        }
        if ((len - i) > 0)
        {
            printf("%.2x ", payload[max - (len - i)]);
        }
        else
        {
            printf("\t");
        }
    }

    if (i < 16)
    {
        int flag = 0;
        flag = 16 - i > 8 ? 1 : 0;
        for (int j = 0; j < 16 - i; j++)
        {
            if (flag)
            {
                if (8-j == 0)
                {
                    printf("  ");
                }
            }
            printf("%s ", "  ");
        }
    }

    printf("  ");
    for (i = 0; i < width; i++) // 打印16个字节的asciipayload
    {
        if (isprint(payload[max - (len - i)])) // 为可打印字符
        {
            printf("%c", payload[max - (len - i)]);
        }
        else // 打印不出来的用"."表示
        {
            printf(".");
        }
    }
}

void print_data(u_char *payload, int len)
{
    int line_width = 16;
    int len_rem = len;
    int maxlen = len;
    int offset = 0;
    while (1)
    {
        if (len_rem < line_width)
        {
            if (len_rem == 0)
                break;
            else
            {
                print(payload, len_rem, offset, maxlen, len_rem, 1);
                offset = offset + len_rem;
                printf("\n");
                break;
            }
        }
        else
        {
            print(payload, len_rem, offset, maxlen, line_width, 0);
            offset = offset + 16;
            printf("\n");
        }
        len_rem = len_rem - line_width;
    }
}

pcap_handler callback(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    struct ether_header *eth;
    struct ip *iph;       // IP包头部
    struct icmphdr *icmp; // ICMP包头部
    struct tcphdr *tcph;  // tcp头部
    struct udphdr *udph;  // udp头部
    int i;
    unsigned int type;

    printf("Pkt Num = %ld\n", ++packet_num);
    printf("Pkt Length = %ld\n", h->len);

    eth = (struct ether_header *)p;

    printf("Source Mac Addr: ");

    for (i = 0; i < 5; i++)
    {
        printf("%.2x:", eth->ether_shost[i]);
    }
    printf("%.2x\n", eth->ether_shost[i]);

    printf("Destination Mac Addr: ");

    for (i = 0; i < 5; i++)
    {
        printf("%.2x:", eth->ether_shost[i]);
    }
    printf("%.2x\n", eth->ether_shost[i]);

    type = ntohs(eth->ether_type);
    printf("====>Network Layer Protocal:");
    switch (type)
    {
    case ETHERTYPE_IP:
        printf("IPV4\n");
        break;
    case ETHERTYPE_IPV6:
        printf("IPV6\n");
    default:
        printf("unknown network layer types\n");
    }
    printf("\n");
    if (type == ETHERTYPE_IP)
    {
        iph = (struct ip *)(eth + 1);

        printf("Source Ip Address:");
        printf("%s\n", inet_ntoa(iph->ip_src));

        printf("Destination Ip address:");
        printf("%s\n", inet_ntoa(iph->ip_dst));
        printf("\n");

        printf("====>Transport layer protocal:");
        if (iph->ip_p == 1)
        {
            printf("ICMP\n");
        }
        else if (iph->ip_p == 2)
        {
            printf("IGMP\n");
        }
        else if (iph->ip_p == 6) // 为TCP协议
        {
            printf("TCP\n");
            tcph = (struct tcphdr *)(p + sizeof(struct ether_header) + sizeof(struct ip)); // 获得tcp头部地址
            printf("Dest port:%d\n", ntohs(tcph->dest));                                   // 打印目的端口号
            printf("Source port:%d\n", ntohs(tcph->source));                               // 打印源端口号
            printf("Payload");
            printf("(%d bytes): \n", h->len);
            print_data(p, h->len);
        }
        else if (iph->ip_p == 17) // 为UDP协议
        {
            printf("UDP\n");
            udph = (struct udphdr *)(p + sizeof(struct ether_header) + sizeof(struct ip)); // 获得udp头部地址
            printf("dest port:%d\n", ntohs(udph->dest));                                   // 打印目的端口号
            printf("source port:%d\n", ntohs(udph->source));                               // 打印源端口号
            printf("Payload");
            printf("(%d bytes): \n", h->len);
            print_data(p, h->len);
        }
        else
        {
            printf("unknown protocol\n");
        }
    }

    printf("\n-------------------------------------------------------------\n");
}

int main(int argc, char **argv)
{
    char *dev = NULL;      // device name
    char *netAddr = NULL;  // net addr
    char *maskAddr = NULL; // mask addr
    struct in_addr addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct bpf_program fp;
    char filter_exp[] = "tcp";

    struct pcap_pkthdr header;
    const u_char *packet;

    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    printf("Device: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        exit(-1);
    }

    // 转换网络字节顺序到主机字节顺序
    addr.s_addr = net;
    netAddr = inet_ntoa(addr);
    printf("NetAddr: %s\n", netAddr);

    addr.s_addr = mask;
    maskAddr = inet_ntoa(addr);
    printf("MaskAddr: %s\n", maskAddr);

    printf("================><==================\n");
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, mask) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    if (pcap_loop(handle, -1, callback, NULL) < 0)
    {
        (void)fprintf(stderr, "pcap_loop:%s\n", pcap_geterr(handle));
        exit(0);
    }

    pcap_close(handle);
    return (0);
}