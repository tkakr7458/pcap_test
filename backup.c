#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

struct mac{
    u_int8_t dest_addr[6];
    u_int8_t src_addr[6];
    u_int16_t d_type;
};

struct ethernet
{
    unsigned int ip_v:4;    /* version */
    unsigned int ip_hl:4;    /* header length */
    u_int8_t ip_tos;      /* type of service */
    u_short ip_len;      /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;      /* fragment offset field */
    u_int8_t ip_ttl;      /* time to live */
    u_int8_t ip_p;      /* protocol */
    u_short ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dest; 
};

struct tcp
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns:1;
    unsigned char reserved_part1:3;
    unsigned char data_offset:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};




int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int status;

    /* Define the device */
    dev = argv[1];
    
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    /* Grab a packet */
    int ppp = 0;
	while(1)
	{	   
        packet=pcap_next(handle, &header);

        struct mac * mac_addr;
        mac_addr = (struct mac *)packet;
	

	struct ethernet * IPheader;
        packet += sizeof(struct mac);
        IPheader = (struct ethernet *)packet;

	struct tcp * TCPheader;
        TCPheader = (struct tcp *)(packet + IPheader->ip_v * 4);
	
	printf("ip4 cheak!! : %x\n",mac_addr->d_type);
	if(mac_addr->d_type==6)
	printf("This is ipv4 !!! :\n");
		
        printf("==============MAC===============\n");
        printf("Src_MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            (unsigned)mac_addr->src_addr[0],
            (unsigned)mac_addr->src_addr[1],
            (unsigned)mac_addr->src_addr[2],
            (unsigned)mac_addr->src_addr[3],
            (unsigned)mac_addr->src_addr[4],
            (unsigned)mac_addr->src_addr[5]);
        printf("Dest_MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            (unsigned)mac_addr->dest_addr[0],
            (unsigned)mac_addr->dest_addr[1],
            (unsigned)mac_addr->dest_addr[2],
            (unsigned)mac_addr->dest_addr[3],
            (unsigned)mac_addr->dest_addr[4],
            (unsigned)mac_addr->dest_addr[5]);

 
        printf("==============IP================\n");
        printf("Src Address : %s\n", inet_ntoa(IPheader->ip_src));
        printf("Dest Address : %s\n", inet_ntoa(IPheader->ip_dest));

        

        if(ntohs(TCPheader->dest_port) == 80 || ntohs(TCPheader->source_port)==80)
        {
            printf("=============PORT===============\n");
            printf("Src_Port : %d\n" , ntohs(TCPheader->source_port));
            printf("Dest_Port : %d\n\n\n" , ntohs(TCPheader->dest_port));
        }
	else
	{
		printf("TCPheader.dest_port !!!Error!!!\n");
		return 0;
	}

        int num=0;
        int sf = ((header.len)-sizeof(packet));
        printf("packet len : %d\n",sf);
	
	
	int backup = sf;
	while(sf--)
        {
            num++;
            if(num%16 == 0)
            {
                printf("\n");
            }
            else
            {
                printf("%02x", *(packet++));
            }
		if(num==backup)
			return 0;
        }
	
    }
    pcap_close(handle);
    return(0);
}
