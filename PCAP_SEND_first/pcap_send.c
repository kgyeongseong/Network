#include <pcap.h>
#include <stdlib.h>

int main()
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    __u_char packet[100];
    int i;
    char *dev;
    int ret;

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

    // set mac destination to 1:1:1:1:1:1
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 1;
    packet[3] = 1;
    packet[4] = 1;
    packet[5] = 1;
    
    // set mac source to 2:2:2:2:2:2
    packet[6] = 2;
    packet[7] = 2;
    packet[8] = 2;
    packet[9] = 2;
    packet[10] = 2;
    packet[11] = 2;

    // Fill the rest of the packet
    for (i = 12; i < 100; i++)
    {
        packet[i] = i % 256;
    }

    // send down the packet
    if (pcap_sendpacket(fp, packet, 100) != 0)
    {
        printf("%s\n", pcap_geterr(fp));
        exit(1);
    }

    return 0;
}
