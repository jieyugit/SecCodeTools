#include <stdio.h>
#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // 在这里处理数据包，可以实现过滤、修改、记录等逻辑
    printf("%d\n",strlen(packet));
}

int main() {
    char *dev; // 网卡设备名称
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 获取默认网络接口
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // 打开网络接口
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 设置过滤规则，这里只捕获TCP协议的数据包
    struct bpf_program fp;
    char filter_exp[] = "udp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // 开始捕获数据包
    pcap_loop(handle, 0, packet_handler, NULL);

    // 关闭捕获会话
    pcap_close(handle);

    return 0;
}
