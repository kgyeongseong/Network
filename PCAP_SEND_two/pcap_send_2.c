#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>

struct eth_hdr { // 이더넷 헤더
    unsigned char h_dest[6]; // Dst MAC
    unsigned char h_source[6]; // Src MAC
    unsigned short h_type; // Network Layer Type
};

struct arp_hdr { // ARP 헤더
    unsigned short ar_hdr; // 하드웨어 주소 타입. 이더넷은 1 (2byte)
    unsigned short ar_pro; // 프로토콜 타입. IP는 0x0800 (2byte)
    unsigned char ar_hln; // 하드웨어 주소 길이 1바이트. MAC 주소 길이는 6
    unsigned char ar_pln; // 프로토콜 주소 길이 1바이트. IP 주소 길이는 4
    unsigned short ar_op; // op코드. 요청 or 응답. request 1, reply 2
    unsigned char ar_sha[6]; // 출발지 MAC 주소
    unsigned char ar_sip[4]; // 출발지 IP 주소
    unsigned char ar_tha[6]; // 목적지 MAC 주소 (이걸 채우려고 ARP 쓰므로 처음엔 비어있다.)
    unsigned char ar_tip[4]; // 목적지 IP 주소
};

// 패킷 총 길이
static unsigned char g_buf[sizeof(struct eth_hdr) + sizeof(struct arp_hdr)];

int main()
{
    // ARP 패킷 만드는 과정
    // 헤더 구조에 맞춰서 구조체를 만들어 주고, 각 값을 채운다
    // 패킷을 보낸다
    struct eth_hdr ether;
    struct arp_hdr arp;

    // 이데넛의 목적지 주소 6바이트를 브로드캐스트로 채움
    ether.h_dest[0] = 0xff;
    ether.h_dest[1] = 0xff;
    ether.h_dest[2] = 0xff;
    ether.h_dest[3] = 0xff;
    ether.h_dest[4] = 0xff;
    ether.h_dest[5] = 0xff;

    // 이더넷 출발지 주소 6바이트. 어차피 내가 만드는 헤더라 임의로
    ether.h_source[0] = 0x00;
    ether.h_source[1] = 0x01;
    ether.h_source[2] = 0x02;
    ether.h_source[3] = 0x03;
    ether.h_source[4] = 0x04;
    ether.h_source[5] = 0x05;

    // short형 호스트 바이트 순서 데이터를 네트워크 바이트 순서값으로 변환
    ether.h_type = htons(0x0806); // Network Layer Type = ARP

    arp.ar_hdr = htons(0x0001); // 하드웨어 주소 타입 - 이더넷은 1
    arp.ar_pro = htons(0x0800); // 프로토콜 주소 타입 - IP는 0x0800
    arp.ar_hln = 0x06; // 하드웨어 주소 길이 - MAC 주소 길이 6
    arp.ar_pln = 0x04; // 프로토콜 주소 길이 - IP 주소 길이 4
    arp.ar_op = htons(0x0001); // op코드 - ARP 요청 0x0001

    // 출발지 MAC 주소 - 내가 헤더 만들고 있으니까 임의로 채움
    arp.ar_sha[0] = 0x00;
    arp.ar_sha[1] = 0x01;
    arp.ar_sha[2] = 0x02;
    arp.ar_sha[3] = 0x03;
    arp.ar_sha[4] = 0x04;
    arp.ar_sha[5] = 0x05;

    // 출발지 IP 주소
    arp.ar_sip[0] = 0x00;
    arp.ar_sip[1] = 0x01;
    arp.ar_sip[2] = 0x02;
    arp.ar_sip[3] = 0x03;

    // 목적지 MAC 주소 - 처음 통신할 때는 비어있다.
    arp.ar_tha[0] = 0x00;
    arp.ar_tha[1] = 0x00;
    arp.ar_tha[2] = 0x00;
    arp.ar_tha[3] = 0x00;
    arp.ar_tha[4] = 0x00;
    arp.ar_tha[5] = 0x00;

    // 목적지 IP 주소
    arp.ar_tip[0] = 0x00;
    arp.ar_tip[1] = 0x01;
    arp.ar_tip[2] = 0x02;
    arp.ar_tip[3] = 0x03;
    arp.ar_tip[4] = 0x04;
    arp.ar_tip[5] = 0x05;

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *fp;
    // 사용중인 디바이스 이름을 얻어온다.
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    // Open the output device
    fp = pcap_open_live(dev, 100, 0, 1000, errbuf);
    if (fp == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 이더넷 헤더 크기 만큼
    // 만든 이더넷 헤더 복사
    memcpy(g_buf, &ether, sizeof(struct eth_hdr));
    // ARP 헤더 크기 만큼
    // 만든 ARP 헤더 복사
    memcpy(g_buf+14, &arp, sizeof(struct arp_hdr));

    // 첫 번째 인자 : pcap_t *p
    // 두 번째 인자 : const void *buf
    // 세 번째 인자 : size_t size = 보낼 패킷의 바이트 수
    if (pcap_sendpacket(fp, g_buf, sizeof(g_buf)) != 0)
    {
        printf("%s\n", pcap_geterr(fp));
        exit(1);
    }

    return 0;
}
