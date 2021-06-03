#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <stdlib.h>

int main()
{
    char *dev; // 사용중인 네트웍 디바이스 이름
    char *net; // 네트웍 어드레스
    char *mask; // 네트웍 mask 어드레스
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp; // ip
    bpf_u_int32 maskp; // subnet mask
    struct in_addr addr;

    // 네트웍 디바이스 이름을 얻어온다.
    dev = pcap_lookupdev(errbuf);

    // 에러가 발생했을경우
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 네트웍 디바이스 이름 출력
    printf("DEV: %s\n", dev);

    // 네트웍 디바이스 이름 dev에 대한
    // mask, ip 정보 얻어오기
    // 첫 번째 인자 : pcap_lookupdev 등을 통해 얻어온 네트웍 디바이스 이름
    // 두 번째 인자 : 네트웍 번호
    // 세 번째 인자 : mask 번호
    // 네 번째 인자 : 에러가 발생할 경우 -1이 리턴되며, 에러 내용이 errbuf에 저장된다
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 네트웍 어드레스를 점박이 3형제 스타일로
    addr.s_addr = netp;
    // 네트워크 주소 변환
    // ex) 0x6601a8c0 -> 192.168.1.102
    net = inet_ntoa(addr);

    if (net == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("NET: %s\n", net);

    // 마찬가지로 mask 어드레스를 점박이 3형제 스타일로
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    if (mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("MASK: %s\n", mask);
    
    return 0;
}
