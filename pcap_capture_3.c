#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// 이더넷 프레임 구조체 선언
#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
    // __u_char = unsigned char (1byte)
    // __u_short = unsigned short (2byte)
    __u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
    __u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
    __u_short ether_type; // Network Layer 타입 종류
};

#define IP_HL(ip) (((ip)->ip_vhl) &0x0f) // IP 헤더 프로토콜 헤더 길이 (4bit) 
#define IP_V(ip) (((ip)->ip_vhl) >> 4) // IP 버전 (4bit)
struct sniff_ip {
    // __u_char (1byte)
    // __u_short (2byte)
    __u_char ip_vhl; // (IP 헤더) version (4bit) + (IP 헤더) 프로토콜 헤더 길이 (4bit) 
    __u_char ip_tos; // (IP 헤더) Type Of Service (1byte)
    __u_short ip_len; // (IP 헤더) IP 패킷의 전체 크기 (2byte)
    __u_short ip_id; // (IP 헤더) 식별번호 (2byte)
    __u_short ip_off; // (IP 헤더) Flags (3bit) + (IP 헤더) Fragment Offset (13bit)
    #define IP_RF 0x8000 // Reserved Fragment flag
    #define IP_DF 0x4000 // Dont Fragment flag
    #define IP_MF 0x2000 // More Fragments flag
    #define IP_OFFMASK 0x1fff // Mask for Fragmenting bits
    __u_char ip_ttl; // (IP 헤더) Time To Live (1byte)
    __u_char ip_p; // (IP 헤더) Transport Layer 프로토콜 종류 (1byte)
    __u_short ip_sum; // (IP 헤더) Header Checksum (2byte)
    struct in_addr ip_src; // 출발지 IP 주소 (4byte)
    struct in_addr ip_dst; // 목적지 IP 주소 (4byte)
};

// __u_int = unsigned int (4byte)
typedef __u_int tcp_seq;
struct sniff_tcp {
    // __u_short (2byte)
    __u_short th_sport; // (TCP 헤더) 출발지 PORT 주소 (2byte)
    __u_short th_dport; // (TCP 헤더) 목적지 PORT 주소 (2byte)
    tcp_seq th_seq; // (TCP 헤더) Sequence Number (4byte)
    tcp_seq th_ack; // (TCP 헤더) Acknowledge Number (4byte)
    __u_char th_offx2; // (TCP 헤더) Header Length (4bit) + (TCP 헤더) Reserved (4bit)
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    __u_char th_flags; // (TCP 헤더) Flags (1byte)
    #define TH_FIN 0x01 // FIN : 데이터 전송을 종료한다.
    #define TH_SYN 0x02 // SYN : 통신 시작 시 연결을 요청하고 ISN을 교환한다.
    #define TH_RST 0x04 // RST : 송신자가 유효하지 않은 연결을 시도할 때 거부하는데 이용되고
                        //       또한 통신의 연결 및 종료를 정상적으로 할 수 없을 때 사용된다.
    #define TH_PSH 0x08 // PSH : 일반적으로 모든 데이터를 전송하고 마지막에 보내는 신호로
                        //       수신측은 데이터를 즉시 전송하라는 의미이다.
    #define TH_ACK 0x10 // ACK : SYN에 대한 확인의 의미이다.
                        //       3Way-Handshacking에서의 SYN과 reset을 제외하고 모든 세그먼트에 ACK가 설정된다.
    #define TH_URG 0x20 // URG : Urgent Point 필드와 함께 사용되고 플래그 설정 시
                        //       TCP는 해당 세그먼트를 전송 큐의 제일 앞으로 보낸다.
    #define TH_ECE 0x40 // ECE : 혼잡 감지시 ECE를 설정하여 송신자에게 알린다.
    #define TH_CWR 0x80 // CWR : 송신자가 자신의 윈도우 사이즈를 줄인다.
    #define TH_FLAGS (TH_FIL | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    __u_short th_win; // (TCP 헤더) Window Size
    __u_short th_sum; // (TCP 헤더) Checksum
    __u_short th_urp; // (TCP 헤더) Urgent Point
};

#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip; // IP 헤더
struct sniff_tcp *tcp; // TCP 헤더
char *payload; // TCP 페이로드

__u_int size_ip;
__u_int size_tcp;

char *dev;
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
bpf_u_int32 net; // 아이피 주소
bpf_u_int32 mask; // 서브넷 마스크
struct in_addr addr; // 주소 정보
pcap_t *handle; // 핸들러
struct bpf_program fp; // 필터 구조체
struct pcap_pkthdr *header; // 패킷 관련 정보
const __u_char *packet;
char *filter_exp = "port 80";
int ret;

void parsing()
{
    printf("--------------------------------\n");
    int i, payload_len;
    ethernet = (struct sniff_ethernet *)(packet);
    printf("MAC 출발지 주소 : ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x ", ethernet->ether_shost[i]);
    }
    printf("\nMAC 목적지 주소 : ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x ", ethernet->ether_dhost[i]);
    }
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    printf("\nIP 출발지 주소 : %s\n", inet_ntoa(ip->ip_src));
    printf("IP 목적지 주소 : %s\n", inet_ntoa(ip->ip_dst));
    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    printf("출발지 포트 : %d\n", ntohs(tcp->th_sport));
    printf("목적지 포트 : %d\n", ntohs(tcp->th_dport));
    payload = (__u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (payload_len == 0) printf("페이로드 데이터가 없습니다.");
    else
    {
        printf("< 페이로드 데이터 >\n");
        for (int i = 1; i < payload_len; i++)
        {
            printf("%02x ", payload[i - 1]);
            if (i % 8 == 0) printf("  ");
            if (i % 16 == 0) printf("\n");
        }
    }
    printf("-------------------------------------\n");
}

int main(int argc, char argv[])
{
    

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(0);
    }
    printf("나의 네트워크 장치 : %s\n", dev);
    ret = pcap_lookupnet(dev, &net, &mask, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
        
    addr.s_addr = net;
    //printf("나의 IP주소 : %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    //printf("나의 서브넷 마스크 : %s\n", inet_ntoa(addr));

    handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf);
    if (handle == NULL) {
        printf("%s\n", errbuf);
        exit(0);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("%s\n", errbuf);
        exit(0);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("%s\n", errbuf);
        exit(0);
    }

    // pcap_next_ex()는 캡처된 패킷 내용을 packet 변수에 담습니다.
    // pcap_next_ex()는 성공적으로 수행이 되면 1을 반환합니다.
    // 시간초과가 발생하면 0을 반환합니다.
    // 그리고 패킷을 읽는 도중에 오류가 발생한 경우 -1을 반환합니다.
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        parsing();
    }

    return 0;
}