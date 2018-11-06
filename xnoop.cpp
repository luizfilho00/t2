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
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <iostream>
#include <string>
#include <vector>

#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64
#define ARP_REQUEST 1
#define ARP_REPLY 2

using namespace std;

//! 1 bytes = 8 bits
//! char    = 8 bits
//! char a:4, b:4 -> a = 4 primeiros bits, 8 = 4 ultimos bits
//! short   = 16 bits
//! int     = 32 bits
//! enp3s0   = interface

struct sockaddr_in source, dest;

typedef struct arphdr {
    u_int16_t htype;    		/* Hardware Type           */
    u_int16_t ptype;    		/* Protocol Type           */
    unsigned char hlen; 		/* Hardware Address Length */
    unsigned char plen; 		/* Protocol Address Length */
    u_int16_t oper;     		/* Operation Code          */
    unsigned char sha[6];      	/* Sender hardware address */
    unsigned char spa[4];      	/* Sender IP address       */
    unsigned char tha[6];      	/* Target hardware address */
    unsigned char tpa[4];      	/* Target IP address       */
}arphdr_t;

int tcp = 0, arp = 0, icmp = 0, udp = 0, ip = 0, this_host = 0, total = 0;
string option = "";
char* ip_local;
bool opt_v = false, opt_V = false, opt_c = false, opt_n = false;

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
void print_eth_address(char* s, unsigned char *eth_addr)
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

    //printf("\n\n***********************UDP Packet*************************\n");

    //printf("\n");
    printf("UDP: ----- UDP Header -----\n");

    printf("UDP:   |-Source Port      : %d\n",ntohs(udph->source));
    printf("UDP:   |-Destination Port : %d\n",ntohs(udph->dest));
    printf("UDP:   |-UDP Length       : %d\n",ntohs(udph->len));
    printf("UDP:   |-UDP Checksum     : %d\n",ntohs(udph->check));
    printf("UDP:\n");
}

/**
* Imprime pacote ICMP
*/
void print_icmp(unsigned char* packet, int size){
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)packet;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph=(struct icmphdr*)(packet + iphdrlen);

    printf("ICMP: ----- ICMP Header -----\n");
    printf("ICMP:   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
        printf("ICMP:  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        printf("ICMP:  (ICMP Echo Reply)\n");
    printf("ICMP:   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("ICMP:   |-Checksum : %d\n",ntohs(icmph->checksum));
    printf("ICMP:\n");
}



/**
* Imprime pacote TCP
*/
void print_tcp(unsigned char* packet, int size){
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)packet;
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen);

    //printf("\n");
    printf("TCP: ----- TCP Header ------\n");
    printf("TCP:   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("TCP:   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("TCP:   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("TCP:   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("TCP:   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf("TCP:   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("TCP:   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("TCP:   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("TCP:   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("TCP:   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("TCP:   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("TCP:   |-Window         : %d\n",ntohs(tcph->window));
    printf("TCP:   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("TCP:   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("TCP:\n");
}

void treat_sign(int signal)
{
    if (signal == SIGINT){
        printf("\nRecebido SIGINT\n");

        printf("ARP : %d   \nIP : %d  \nICMP : %d  \nUDP : %d"
               "\nTCP : %d    \nTo this host : %d	\nTotal : %d  \n", arp, ip, icmp, udp, tcp, this_host, total);
    }

    exit(0);
}

void print_verbose(unsigned char* packet, int len){
    arphdr_t *arpheader = nullptr;
    auto* eth = (struct ether_hdr*) packet;

    if(eth->ether_type == htons(0x0800)) {
        auto *iph = (struct iphdr *)(packet + 14);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;


        print_eth_address(const_cast<char *>(""), eth->ether_dhost);
        cout << " " << inet_ntoa(source.sin_addr) << " -> ";

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        cout << inet_ntoa(dest.sin_addr);

        ip++;

        if (strcmp(inet_ntoa(dest.sin_addr), ip_local) == 0 || strcmp(inet_ntoa(dest.sin_addr), "127.0.0.1") == 0)
            this_host++;

        if (iph->protocol == 6){ // TCP
            unsigned short iphdrlen;
            auto *iph = (struct iphdr *)packet;
            iphdrlen = iph->ihl*4;
            auto *tcph=(struct tcphdr*)(packet + iphdrlen);

            cout << " TCP sourceport=" << ntohs(tcph->source) << " destport=" << ntohs(tcph->dest) << endl;
            tcp++;
        } else if(iph->protocol == 17){ //UDP
            unsigned short iphdrlen;
            auto *iph = (struct iphdr *)packet;
            iphdrlen = iph->ihl*4;

            auto *udph=(struct udphdr*)(packet + iphdrlen);
            cout << " UDP sourceport=" << ntohs(udph->source) << " destport=" << ntohs(udph->dest) << endl;
            udp++;
        } else if(iph->protocol == 1){ // ICMP
            unsigned short iphdrlen;
            auto *iph = (struct iphdr *)packet;
            iphdrlen = iph->ihl*4;

            auto *icmph = (struct icmphdr*)(packet + iphdrlen);
            cout << " ICMP type=" << (unsigned int)(icmph->type) << endl;
            icmp++;
        }
    }else if (eth->ether_type == htons(0x0806)){
        ++arp;
        arpheader = (struct arphdr *)(packet+14);
        for(int i=0; i<6;i++)
            printf("%02X:", arpheader->sha[i]);
        cout << " -> ARP Who is ";
        for(int i=0; i<6;i++)
            printf("%02X:", arpheader->tha[i]);
        cout << endl;
    }

}

void print_verbose_ext(unsigned char* packet, int len){
    arphdr_t *arpheader = nullptr;
    auto* eth = (struct ether_hdr*) packet;

    printf("\nETHER: ----- Ether Header -----\n");
    cout << "ETHER:   |-Packet        : " << total << endl;
    print_eth_address(const_cast<char *>("ETHER:   |-Source        :"), eth->ether_dhost);
    print_eth_address(const_cast<char *>("\nETHER:   |-Destination   :"), eth->ether_shost);
    printf("\nETHER:   |-Ethertype   : 0x%04X", ntohs(eth->ether_type));
    if (eth->ether_type == htons(0x0800))
        printf(" (IP)");
    else if (eth->ether_type == htons(0x0806))
        printf(" (ARP)");
    printf("\nETHER:   |-Size   :%d", len);
    printf("\nETHER:\n");

    if(eth->ether_type == htons(0x0800)) {
        //IP
        auto *iph = (struct iphdr *)(packet + 14);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        //printf("\n");
        printf("IP: ----- IP Header -----\n");
        printf("IP:   |-IP Version        : %d\n", iph->version);
        printf("IP:   |-IP Header Length  : %d DWORDS or %d Bytes\n", iph->ihl,((iph->ihl))*4);
        printf("IP:   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
        printf("IP:   |-IP Total Length   : %d  Bytes\n",ntohs(iph->tot_len));
        printf("IP:   |-Identification    : %d\n",ntohs(iph->id));
        printf("IP:   |-TTL      : %d\n",(unsigned int)iph->ttl);
        printf("IP:   |-Protocol : %d\n",(unsigned int)iph->protocol);
        printf("IP:   |-Checksum : %d\n",ntohs(iph->check));
        printf("IP:   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
        printf("IP:   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
        printf("IP:\n");

        if (strcmp(inet_ntoa(dest.sin_addr), ip_local) == 0 || strcmp(inet_ntoa(dest.sin_addr), "127.0.0.1") == 0)
            this_host++;

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
        ++arp;
        arpheader = (struct arphdr *)(packet+14);
        //printf("\n");
        printf("ARP: ----- ARP Header -----\n");
        printf("ARP:   |-Hardware type: %d\n",(unsigned int)(arpheader->htype));
        printf("ARP:   |-Protocol type: 0x%04X\n", ntohs(arpheader->ptype));
        printf("ARP:   |-Length of hardware adress: %d\n", ((unsigned int)arpheader->hlen))*4;
        printf("ARP:   |-Length of protocol adress: %d\n", ((unsigned int)arpheader->plen))*4;
        printf("ARP:   |-Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

        printf("ARP:   |-Sender's hardware adress: ");
        for(int i=0; i<6;i++)
            printf("%02X:", arpheader->sha[i]);
        printf("\n");

        printf("ARP:   |-Sender's protocol adress: ");
        for(int i=0; i<4;i++)
            printf("%d.", arpheader->spa[i]);
        printf("\n");

        printf("ARP:   |-Target hardware adress: ");
        for(int i=0; i<6;i++)
            printf("%02X:", arpheader->tha[i]);
        printf("\n");

        printf("ARP:   |-Target protocol adress: ");
        for(int i=0; i<4;i++)
            printf("%d.", arpheader->tpa[i]);
        printf("\n");
    }
    fflush(stdout);
}

/* */
// Break this function to implement the functionalities of your packet analyser
void doProcess(unsigned char* packet, int len, int num_packets) {
    if(!len || len < MIN_PACKET_SIZE)
        return;
    total++;

    if (opt_c && total == num_packets + 1)
        exit(0);
    if (opt_v){
        print_verbose(packet, len);
    }
    if (opt_V){
        print_verbose_ext(packet, len);
    }
    if (!opt_v && !opt_V && !opt_n && !opt_c){
        auto* eth = (struct ether_hdr*) packet;
        if(eth->ether_type == htons(0x0800)) { //IP
            ip++;
            auto *iph = (struct iphdr *) (packet + 14);
            if (iph->protocol == 6){ // TCP
                tcp++;
            } else if(iph->protocol == 17){ //UDP
                udp++;
            } else if(iph->protocol == 1){ // ICMP
                icmp++;
            }
        }
        else if (eth->ether_type == htons(0x0806)){ //ARP
            ++arp;
        }
    }
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
    int	n, num_packets = 0;
    int	sockfd;
    socklen_t saddr_len;
    struct sockaddr	saddr{};
    unsigned char *packet_buffer;
    vector<string> options;

    if (argc < 3)
        print_usage();

    if (strcmp(argv[1], "-i") != 0)
        print_usage();

    if (argc >= 4) {
        for (int i = 3; i < argc; i++) {
            options.emplace_back(argv[i]);
        }
        for (string opt : options){
            if (opt.find("-c") != -1){
                opt_c = true;
            }
            else if (opt.find("-v") != -1){
                opt_v = true;
            }
            else if (opt.find("-V") != -1){
                opt_V = true;
            }
            else if (opt.find("-n") != -1){
                opt_n = true;
            }else{
                num_packets = atoi(opt.c_str());
            }
        }
    }

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

    packet_buffer = new unsigned char[MAX_PACKET_SIZE];

    //Pegar IP Local

    struct ifreq req{};
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, argv[2], IF_NAMESIZE - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &req) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    ip_local = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);

    while(true) {
        n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
        if(n < 0) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            exit(1);
        }

        //Get local ip address before analyse packets
        doProcess(packet_buffer, n, num_packets);

        if (signal(SIGINT, treat_sign) == SIG_ERR) {
            printf("\nNao captura SIGINT\n");
            break;
        }
    }

    free(packet_buffer);
    close(sockfd);

    return 0;
}
/* */
