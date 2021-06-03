#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#define NONPROMISCUOUS 0
#define PROMISCUOUS 1
#define TCPHEADERSIZE 6*4

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// 패킷을 받아들일 경우 이 함수를 호출한다.
// packet 가 받아들인 패킷이다.
void callback(__u_char *useless, const struct pcap_pkthdr *pkthdr,
                const __u_char *packet)
{
    struct ether_header *ep;
    unsigned short ether_type;

    char *uid = NULL;
    char *passw = NULL;
    char buf[80];

    // 이더넷 헤더를 가져온다.
    // 캡처로 받아들인 패킷의 이더넷 헤더의 시작점을 저장
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서
    // 이더넷 헤더 크기만큼 offset 한다
    // 받아들인 패킷의 Ethernet header의 시작점 + Ethernet header size
    // = 받아들인 패킷의 IP header의 시작점
    packet += sizeof(struct ether_header);
    // Network Layer 의 Protocol 타입을 저장하고 있음
    ether_type = ntohs(ep->ether_type);

    // Network Layer 의 Protocol 타입을 알아낸다.
    // 만약 IP 프로토콜을 사용한다면
    // IP 정보를 얻어온다.
    if (ether_type == ETHERTYPE_IP)
    {
        // iph에는 IP 헤더의 시작점을 저장
        iph = (struct ip *)packet;
        // 패킷의 IP 헤더 안 프로토콜 정보가 TCP 이면
        if (iph->ip_p == IPPROTO_TCP)
        {
            // IP 헤더에서 데이터 정보를 출력한다.
            iph = (struct ip *)packet;
            
            // 패킷의 IP 헤더 안 프로토콜 정보가 TCP 이고
            // IP 헤더 Header length * 4byte = IP header 전체 길이
            // 받아들인 패킷의 IP header의 시작점 + IP header length = 
            // 받아들인 패킷의 TCP header의 시작점
            tcph = (struct tcp *)(packet + iph->ip_hl *4);
        }

        memset(buf, 0x00, 80);

        // 유저 데이터를 얻어오기 위해서
        // IP, TCP, Ethernet 헤더 크기만큼 offset 한다.
        // 위에서 packet은 받아들인 패킷의 IP header의 시작점을 저장하고 있었음
        // 받아들인 패킷의 IP header의 시작점 + IP header의 전체 길이 = 받아들인 패킷의 TCP header의 시작점
        // 받아들인 패킷의 TCP header의 시작점 + 24byte = 받아들인 패킷의 TCP header 데이터 중 Destination Port 값 중간
        // 받아들인 패킷의 TCP header의 Destination Port 값 위치 중간 + Ehternet hader의 사이즈 = ?
        packet += (iph->ip_hl * 4) + TCPHEADERSIZE + (sizeof(struct ether_header));

        // 패킷에 ID와 passwword 관련 문자열을 포함하는지 확인한다.
        if ( ((uid = strstr(packet, "uid=")) != NULL)
            && ((passw = strstr(packet, "&passw=")) != NULL))
        {
            // 헤더 정보를 출력한 후
            printf("HEADER INFO\n");
            printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

            printf("Src Port : %d\n", ntohs(tcph->source));
            printf("Dst Port : %d\n", ntohs(tcph->dest));

            // 문자열에서 필요한 정보 즉 ID와 passwword 만을
            // 추출해 낸다.
            strncpy(buf, uid+4, strstr(uid, "&") - (uid + 4));
            printf("uid : <%s>\n", buf);
            memset(buf, 0x00, 80);
            strncpy(buf, passw+7, strstr(passw+7, "&") - (passw + 7));
            printf("passw : <%s>\n", buf);
            printf("================\n\n");
        }
    }
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

    struct bpf_program fp;

    pcap_t *pcd; // packet capture descriptor

    // 디바이스 이름을 얻어온다.
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);
    // 디바이스에 대한 네트웍 정보를 얻어온다.
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 네트웍 정보를 사람이 보기 쉽도록
    // 변환한 다음 출력한다.
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET :%s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MSK: %s\n", mask);
    printf("===============\n");

    // 디바이스에 대한 packet capture descriptor
    // 를 얻어온다.
    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 컴파일 옵션을 준다.
    // 들어오는 패킷을 필터링 해서 받아들이기 위해서 사용한다.
    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }
    // 컴파일 옵션대로 필터룰을 세팅한다.
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    // 지정된 횟수만큼 패킷캡쳐를 한다.
    // pcap_setfilter 을 통과한 패킷에 대해서
    // callback 함수를 호출한다.
    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}