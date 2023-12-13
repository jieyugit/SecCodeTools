#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>

int main(int argc, char **argv)
{
  char *source_ip_str = argv[1];
  char *destination_ip_str = argv[2];
  int i;

  libnet_t *l = NULL;
  libnet_ptag_t protocol_tag;
  char *payload = NULL;
  u_short payload_length = 0;
  char *device = "ens33";

  u_long source_ip = 0;
  u_long destination_ip = 0;
  char errbuf[LIBNET_ERRBUF_SIZE];
  int packet_length;
  l = libnet_init(LIBNET_RAW4, device, errbuf);
  source_ip = libnet_name2addr4(l, source_ip_str, LIBNET_RESOLVE);

  destination_ip = libnet_name2addr4(l, destination_ip_str, LIBNET_RESOLVE);

  protocol_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 123, 456, NULL, 0, l, 0);
  protocol_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_length, 0, 10, 0, 20, 
  IPPROTO_ICMP, 0, source_ip, destination_ip, payload, payload_length, l, 0);
  while (1)
  {
    packet_length = libnet_write(l); /* 发送由libnet句柄l表示的数据包 */
    printf("%d bytes written.\n ", packet_length);
    /* 输出发送的数据包信息 */
  }
  libnet_destroy(l); /* 销毁libnet */
}