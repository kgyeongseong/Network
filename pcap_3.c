#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

int main(void)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;

    char errbuf[PCAP_ERRBUF_SIZE];

    // 네트워크 디바이스의 목록을 알려주는 함수이다.
    // int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
    // alldevsp라는 구조체 포인터를 통해 목록과 특성을 알려준다.
    // 성공시 0을, 실패시 -1을 반환하고 errbuf변수를 채운다. 
    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("%s\n", errbuf);
        exit(1);
    }
    if (!alldevs) {
        printf("%s\n", errbuf);
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);

        if (d->description) printf(" (%s) ", d->description);
        printf("\n");
    }

    // pcap_findalldevs() 함수로 인해 메모리가 동적으로 할당된 것을
    // 사용 후 메모리를 해제해주는 역할을 한다.
    pcap_freealldevs(alldevs);

    return 0;
}