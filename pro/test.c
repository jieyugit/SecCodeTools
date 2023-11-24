#include <stdio.h>
#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // �����ﴦ�����ݰ�������ʵ�ֹ��ˡ��޸ġ���¼���߼�
    printf("%d\n",strlen(packet));
}

int main() {
    char *dev; // �����豸����
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // ��ȡĬ������ӿ�
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // ������ӿ�
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // ���ù��˹�������ֻ����TCPЭ������ݰ�
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

    // ��ʼ�������ݰ�
    pcap_loop(handle, 0, packet_handler, NULL);

    // �رղ���Ự
    pcap_close(handle);

    return 0;
}
