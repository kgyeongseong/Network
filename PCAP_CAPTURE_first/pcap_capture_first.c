#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// 패킷을 받아들일경우 이 함수를 호출한다.
// packet 가 받아들인 패킷이다.
void callback(__u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const __u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt = 0;
    int length = pkthdr->len;

    /* 
    * Ethernet 헤더와 IP 헤더의 경우 demultiplexing 과정을 거치기 위해서
    * 상위 Layer의 프로토콜 타입을 지정하고 있다.
    * Ethernet 헤더의 h_proto와 IP 헤더의 ip_p가 각 상위 Layer 의
    * 프로토콜 타입을 알려주기 위해서 사용된다.
    */
    /*
    * 운영체제가 패킷을 받으면 가장 먼저 Link 레이어(Layer 2)를 거치는데,
    * Link 레이어에서는 Ethernet 헤더를 분석해서
    * 패킷이 Network 레이어로 전달되는 패킷인지 확인해서
    * Network 레이어로 전달된다면 해당 패킷이 IP 패킷인지
    * 아니면 ICMP, IGMP 와 같은 패킷인지를 검사한 후
    * Network 레이어의 알맞은 처리루틴으로 보낼 것 이다.
    */
    /* 
    * Network 레이어에서는 패킷을 받은 다음 자신의 프로토콜 헤더를 검사해서
    * 이 패킷이 Transport 레이어로 전달되는 패킷인지 확인하고,
    * Transport 레이어로 전달된다면 UDP 인지, TCP 인지를 확인 한 다음에
    * Transport 레이어의 적당한 처리루틴으로 패킷을 던질 것 이다.
    */
    /*
    * 최후에는 TCP 헤더만 남게 되는데, TCP 헤더의 PORT 를 검사해서
    * 어떤 애플리케이션에게 전달되어야 하는지를 최종 결정하게 된다.
    */
    // 이더넷 헤더를 가져온다.
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서
    // 이더넷 헤더 크기만큼 offset 한다
    packet += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다.
    ether_type = ntohs(ep->ether_type);

    // 만약 IP 패킷이라면
    if (ether_type == ETHERTYPE_IP)
    {
        // IP 헤더에서 데이터 정보를 출력한다.
        iph = (struct ip *)packet;
        printf("IP 패킷\n");
        printf("Version : %d\n", iph->ip_v);
        printf("Header Len : %d\n", iph->ip_hl);
        printf("Ident : %d\n", ntohs(iph->ip_id));
        printf("TTL : %d\n", iph->ip_ttl);
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        // 만약 TCP 데이터 라면
        // TCP 정보를 출력한다.
        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n", ntohs(tcph->source));
            printf("Dst Port : %d\n", ntohs(tcph->dest));
        }

        // Packet 데이터를 출력한다.
        // IP 헤더 부터 출력한다.
        while (length--)
        {
            printf("%02x", *(packet++));
            if ((++chcnt %16) == 0)
                printf("\n");
        }
    }
    // IP 패킷이 아니라면
    else
    {
        printf("NONE IP 패킷\n");
    }
    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const __u_char *packet;

    struct bpf_program fp;

    pcap_t *pcd; // packet capture descriptor

    // 사용중인 디바이스 이름을 얻어온다.
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV :%s\n", dev);

    // 디바이스 이름에 대한 네트웍/마스크 정보를 얻어온다.
    // 첫 번째 인자 : pcap_lookupdev를 통해 얻어온 네트웍 디바이스 이름
    // 두 번째 인자 : &netp에 네트웍 정보 저장되는 듯
    // 세 번째 인자 : &maskp에 마스크 정보 저장되는 듯
    // 네 번째 인자 : 에러 발생시 에러 정보
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 네트웍/마스크 정보를 점박이 3형제 스타일로 변경한다
    net_addr.s_addr = netp;
    // inet_ntoa : 192.168.10.1 형식으로 바꿔 줌
    net = inet_ntoa(net_addr);
    printf("NET : %s\n", net);

    mask_addr.s_addr = maskp;
    // 마스크 정보 역시 255.255.255.0 형식으로 바꿔 줌
    mask = inet_ntoa(mask_addr);
    printf("MSK : %s\n", mask);
    printf("==============\n");

    // 디바이스 dev에 대한 packet capture
    // descriptor를 얻어온다.
    // 첫 번째 인자 : 패킷 캡쳐할 네트웍 device
    // 두 번째 인자 : 받아들일 수 있는 패킷의 최대 크기(byte)
    // 세 번째 인자1 : PROMISCUOUS(1)일 경우 로컬 네트웍의 모든 패킷을 캡쳐
    // 세 번째 인자2 : NONPROMISCUOUS(2)일 경우 자기에게만 향하는 패킷을 캡쳐
    // 네 번째 인자 : to_ms는 읽기 시간초과(time out)을 위해서 사용되며 millisecond 단위이다.
    // (주: 네 번째 인자 오타 아닙니다. 입력기 오류로 간이 입력이 안됨)
    // 다섯 번째 인자 : ebuf는 pcap_open_live 함수 호출에 문제가 생겼을 경우 에러 메시지를 저장
    // 만약 pcap_open_live 함수 호출시 에러가 발생할 경우 NULL을 리턴하고
    // 에러 내용을 ebuf에 복사한다
    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 컴파일 옵션을 준다.
    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }
    // 컴파일 옵션대로 패킷필터 룰을 세팅한다.
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    // 지정된 횟수만큼 패킷캡쳐를 한다.
    // pcap_setfilter 을 통과한 패킷이 들어올경우
    // callback 함수를 호출하도록 한다.
    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}
