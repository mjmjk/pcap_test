#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

# define TCP_MAX 10
# define ETHERTYPE_IP 0x0800


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct wireShark{
    
};

void e_header(ether_header * ethernet)
{
    printf("MAC Source Host: ");
    for (int i=0;i<ETH_ALEN-1;i++) {
        printf("%02X:",ethernet->ether_shost[i]);
    }
    printf("%02X",ethernet->ether_shost[5]);
    printf("\n");

    printf("MAC Destination Host: ");
    for (int i=0;i<ETH_ALEN-1;i++) {
        printf("%02X:",ethernet->ether_dhost[i]);
    }
    printf("%02X",ethernet->ether_dhost[5]);
    printf("\n");

}

void ip_header(iphdr *ip)
{
    printf("Source IP: %s \n",inet_ntoa(*(in_addr*)&ip->saddr));
    printf("Destination IP: %s \n",inet_ntoa(*(in_addr*)&ip->daddr));
}

void tcp_header(tcphdr *tcp)
{
    printf("Source Port: %d \n",ntohs(tcp->th_sport));
    printf("Destination Port: %d \n",ntohs(tcp->th_dport));
}


int main(int argc, char* argv[]) {

  struct ether_header *ethernet;
  struct iphdr  *ip;
  struct tcphdr *tcp;
  const u_char *payload;


  const u_char *ip_head;
  const u_char *tcp_head;

  int ethernet_header_length=14;
  int ip_header_length;
  int tcp_header_length;
  int payload_length;





  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);


  //dev ens33
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1; //struct using
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    ethernet = (struct ether_header*)(packet);
    ip = (struct iphdr*)(packet);
    tcp = (struct tcphdr*)(packet);

    ip_head = packet + ethernet_header_length;
    ip_header_length = ((*ip_head)&0x0F);
    ip_header_length = ip_header_length*4;

    u_char protocol = *(ip_head +9);

    tcp_head = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_head +12)) & 0xF0) >>4;
    tcp_header_length = tcp_header_length *4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    payload = packet + total_headers_size;


    printf("=======================\n");

    e_header(ethernet);

    if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
    {
        printf("ether_type is IP \n");
    }

    ip_header(ip);

    if(protocol == IPPROTO_TCP)
    {
        printf("IP protocol type is TCP \n");
    }
    tcp_header(tcp);

    printf("TCP Offset: %u \n",tcp->th_off);
    printf("TCP Window size: %u \n",tcp->window);

    if(payload_length>0)
    {
        printf("TCP payload: ");
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        int ten_count= 10;
        while (byte_count++ < payload_length) {
            printf("%c",u_int(*temp_pointer));
            temp_pointer++;
            ten_count++;
            if(ten_count==10)
            {
                break;
            }
        }
        printf("\n");
    }


    printf("=======================\n");
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
