/* Linux 버전에는 몇 가지 차이점이 있습니다. 
* Linux에서 dns 서버 ips는 /etc/resolv.conf 라는 파일에 저장됩니다. 
* 따라서 get_dns_servers 함수는 이 파일을 열고 dns 서버 IP 주소를 가져옵니다.
*/


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

//List of DNS Servers registered on the system
char dns_servers[10][100];

//Types of DNS resource records :)
#define T_A 1 // IPv4 Address

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Function Prototypes
void ngethostbyname(unsigned char*, int);
void ChangetoDnsNameFormat(unsigned char*, unsigned char*);
unsigned char *ReadName(unsigned char*, unsigned char*, int*);
void get_dns_servers();

int main(int argc, char *argv[])
{
    unsigned char hostname[100];

    //Get the DNS servers from the resolve.conf file
    get_dns_servers();

    //Get the hostname from the terminal
    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    //Now get the ip of this hostname, A record
    ngethostbyname(hostname, T_A);

    return 0;
}

/*
* Perform a DNS query by sending a packet
*/
void ngethostbyname(unsigned char *host, int query_type)
{
    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;

    struct sockaddr_in a;

    struct RES_RECORD answers[20];
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;


    printf("Resolving %s", host);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP Packet for DNS queries

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers

    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    //point to the query portion
    qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];

    ChangetoDnsNameFormat(qname, host);
    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)]; //fill it

    qinfo->qtype = htons(query_type); //type of the query, A, MX, CNAME, NS etc
    qinfo->qclass = htons(1); //its internet (lol)

    printf("\nSending Packet...");
    if ( sendto(s, (char *)buf, sizeof(struct DNS_HEADER) + (strlen((const char *)qname)+1) + sizeof(struct QUESTION), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0 )
    {
        perror("sendto failed");
    }
    printf("Done");

    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");
    if ( recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest, (socklen_t *)&i) < 0 )
    {
        perror("recvfrom failed");
    }
    printf("Done");

    dns = (struct DNS_HEADER *)buf;

    //move ahead of dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname)+1) + sizeof(struct QUESTION)];

    //Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        answers[i].name = ReadName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    //print answers
    printf("\nAnswer Records : %d\n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ", answers[i].name);
        
        if ( ntohs(answers[i].resource->type) == T_A ) // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            a.sin_addr.s_addr = (*p); //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if ( ntohs(answers[i].resource->type) == 5)
        {
            //Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }

        printf("\n");
    }

    return;
}

/*
* Get the DNS servers from /etc/resolv.conf file on Linux
*/
void get_dns_servers()
{
    FILE *fp;
    char line[200], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
    {
        printf("Failed opening /etc/resolve.conf file \n");
    }

    while (fgets(line, 200, fp))
    {
        if (line[0] == '#')
        {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0)
        {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
            // p now is the dns server ip :)
        }
    }

    strcpy(dns_servers[0], p);
}

unsigned char *ReadName(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    //read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader+1;

        if (jumped == 0)
        {
            *count = *count + 1; //if we havent jumped to another location than we can count up
        }
    }

    name[p] = '\0'; //string complete
    if (jumped == 1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; //remove the last dot
    return name;
}

/*
* This will convert www.google.com to 3www6google3com
* got it :)
*/
void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i-lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++; //or lock = i+1;
        }
    }
    *dns++ = '\0';
}