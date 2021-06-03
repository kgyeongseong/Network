#include <pcap.h>
#include <stdlib.h>

char *dev;
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
bpf_u_int32 net; // 아이피 주소
bpf_u_int32 mask; // 서브넷 마스크
struct in_addr addr; // 주소 정보

int main(void)
{
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n");
        exit(0);
    }
    printf("나의 네트워크 장치 : %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("%s\n");
        exit(0);
    }
    addr.s_addr = net;
    printf("나의 IP주소 : %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    printf("나의 서브넷 마스크 : %s\n", inet_ntoa(addr));

    return 0;
}
