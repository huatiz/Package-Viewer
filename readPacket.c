#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

char* ip_ntoa(void *ip);
void dump_udp(const u_char *content);
void dump_tcp(const u_char *content);
void dump_ip(const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Please specify input file.\n");
        exit(1);
    }

    // open saved pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);

    // capture loop
    if (pcap_loop(pcap, -1, pcap_callback, NULL) < 0)
        fprintf(stderr, "[error] pcap_loop: %s\n", pcap_geterr(pcap));

    pcap_close(pcap);

    return 0;
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int id = 0;

    printf("\n-----------------------------\n");
    printf("No. %3d\n\n", ++id);
    printf("Timestamp: %s", ctime((const time_t*)&header->ts.tv_sec));
    
    struct ether_header *ethernet = (struct ether_header *)content;

    u_char *sMac = ethernet->ether_shost;
    u_char *dMac = ethernet->ether_dhost;

    printf("Src MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
    printf("Dst MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", dMac[0], dMac[1], dMac[2], dMac[3], dMac[4], dMac[5]);

    u_int16_t type = ntohs(ethernet->ether_type);
    printf("Ethernet type: 0x%04x ", type);

    switch (type) {
        case ETHERTYPE_IP:
            printf("(IPv4)\n\n");
            dump_ip(content);
            break;
        case ETHERTYPE_IPV6:
            printf("(IPv6)\n");
            break;
        case ETHERTYPE_ARP:
            printf("(ARP)\n");
            break;
        case ETHERTYPE_REVARP:
            printf("(RARP)\n");
            break;
        case ETHERTYPE_PUP:
            printf("(PUP)\n");
            break;
        default:
            printf("\n");
            break;
    }

    return;
}

void dump_ip(const u_char *content) {
    struct ip *ip = (struct ip*)(content + ETHER_HDR_LEN);

    printf("Src IP address: %s\n", ip_ntoa(&ip->ip_src));
    printf("Dst IP address: %s\n", ip_ntoa(&ip->ip_dst));

    u_char protocol = ip->ip_p;
    switch (protocol) {
        case IPPROTO_TCP:
            printf("\n[TCP]\n");
            dump_tcp(content);
            break;
        case IPPROTO_UDP:
            printf("\n[UDP]\n");
            dump_udp(content);
            break;
    }

    return;
}

void dump_tcp(const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    
    printf("Src port: %5u\n", ntohs(tcp->th_sport));
    printf("Dst port: %5u\n", ntohs(tcp->th_dport));

    return;
}
void dump_udp(const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    printf("Src port: %u\n", ntohs(udp->uh_sport));
    printf("Dst port: %u\n", ntohs(udp->uh_dport));

    return;
}

char* ip_ntoa(void *ip) {
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, str, sizeof(str));

    return str;
}