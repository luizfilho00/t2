#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <signal.h>

#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64

//! 1 bytes = 8 bits
//! char    = 8 bits
//! char a:4, b:4 -> a = 4 primeiros bits, 8 = 4 ultimos bits
//! short   = 16 bits
//! int     = 32 bits
struct sockaddr_in source, dest;

int tcp = 0, arp = 0, icmp = 0, udp = 0, ip = 0, total = 0; 
/* */
struct ether_hdr {
	unsigned char	ether_dhost[6];	// Destination address
	unsigned char	ether_shost[6];	// Source address
	unsigned short	ether_type;	// Type of the payload
};

/* */
/* */
// Bind a socket to a interface
int bind_iface_name(int fd, char *iface_name)
{
	return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name));
}
/* */
// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr)
{
	printf("%s %02X:%02X:%02X:%02X:%02X:%02X", s,
	       eth_addr[0], eth_addr[1], eth_addr[2],
	       eth_addr[3], eth_addr[4], eth_addr[5]);
}


/**
* Imprime pacote UDP
*/
void print_udp(unsigned char* packet, int size){
	unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)packet;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph=(struct udphdr*)(packet + iphdrlen);

	printf("\n\n***********************UDP Packet*************************\n");    
    
	printf("\n");
	printf("UDP Header\n");

    printf("   |-Source Port      : %d\n",ntohs(udph->source));
    printf("   |-Destination Port : %d\n",ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n",ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n",ntohs(udph->check));
    printf("\n");
}

/**
* Imprime pacote ICMP
*/
void print_icmp(unsigned char* packet, int size){
	unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)packet;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph=(struct icmphdr*)(packet + iphdrlen);

    printf("\n\n***********************ICMP Packet*************************\n");   
 	printf("ICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11) 
    	printf("  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        printf("  (ICMP Echo Reply)\n");
    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    //printf("   |-ID       : %d\n",ntohs(icmph->id));
    //printf("   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
}



/**
* Imprime pacote TCP
*/
void print_tcp(unsigned char* packet, int size){
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)packet;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen);
             
    printf("\n\n***********************TCP Packet*************************\n");    
         
    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
}

void treat_sign(int signal) 
{ 
    if (signal == SIGINT){
		printf("\nRecebido SIGINT\n");

		printf("ARP : %d   \nIP : %d  \nICMP : %d  \nUDP : %d   \nTCP : %d    \nTotal : %d  \n", arp, ip, icmp, udp, tcp, total);
	}
        
    exit(0); 
} 
/* */
// Break this function to implement the functionalities of your packet analyser
void doProcess(unsigned char* packet, int len) {
	if(!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr* eth = (struct ether_hdr*) packet;
	total++; 
	print_eth_address("\nDst =", eth->ether_dhost);
	print_eth_address(" Src =", eth->ether_shost);
	printf(" Ether Type = 0x%04X Size = %d", ntohs(eth->ether_type), len);
	
	if(eth->ether_type == htons(0x0800)) {
        //IP
		unsigned short iphdrlen;         
        struct iphdr *iph = (struct iphdr *)(packet + 14);
        //iphdrlen = iph->ip_len;
        
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        printf("\n");
        printf("IP Header\n");
        printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
        printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
        printf("   |-Identification    : %d\n",ntohs(iph->id));
        //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
        //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
        //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
        printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
        printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
        printf("   |-Checksum : %d\n",ntohs(iph->check));
        printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
        printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

        if (iph->protocol == 6){ // TCP
            print_tcp(packet, sizeof(packet));
			tcp++;
		} else if(iph->protocol == 17){ //UDP
			print_udp(packet, sizeof(packet));
			udp++;
		} else if(iph->protocol == 1){ // ICMP
			print_icmp(packet, sizeof(packet));
			icmp++;
		}

		ip++; 
	} else if(eth->ether_type == htons(0x0806)) {
		//ARP
		
		//...
		arp++;
	}
	fflush(stdout);
}

/* */
// Print the expected command line for the program
void print_usage()
{
	printf("\nxnoop -i <interface> [options] [filter]\n");
	printf("interface: interface name of each package will be read\n");
	//printf("options:\n   -c n\n   -n\n   -v\n   -V\n");

	exit(1);
}

/* */
// main function
int main(int argc, char** argv) {
	int		n;
	int		sockfd;
	socklen_t	saddr_len;
	struct sockaddr	saddr;
	unsigned char	*packet_buffer;

	if (argc < 3)
		print_usage();
	
	if (strcmp(argv[1], "-i"))
		print_usage();	

	// if (strcmp(argc == 3) {

	// }
	
	saddr_len = sizeof(saddr);
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));  
	if(sockfd < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
	
	if (bind_iface_name(sockfd, argv[2]) < 0) {
		perror("Server-setsockopt() error for SO_BINDTODEVICE");
		printf("%s\n", strerror(errno));
		close(sockfd);
		exit(1);
	}

	packet_buffer = malloc(MAX_PACKET_SIZE);
	if (!packet_buffer) {
		printf("\nCould not allocate a packet buffer\n");		
		exit(1);
	}
	
	while(1) {
		n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
		if(n < 0) {
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(1);
		}
		doProcess(packet_buffer, n);
		
		if (signal(SIGINT, treat_sign) == SIG_ERR) 
          	printf("\nNao captura SIGINT\n"); 
	}

	free(packet_buffer);
	close(sockfd);

	return 0;
}
/* */
