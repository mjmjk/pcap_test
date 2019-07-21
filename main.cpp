#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netinet/tcp.h>//
#include <net/ethernet.h>
#include <netinet/ip.h>

# define TCP_MAX 10
# define ETHERTYPE_IP 0x0800//


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");//
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
    //ip구조체의 주소를 가져와 struct in_addr구조체로 형변환 한다음
    //ip구조체 안에있는 saddr의 값을 가져오기 위해 *를 해준다.
    printf("Destination IP: %s \n",inet_ntoa(*(in_addr*)&ip->daddr));
    /*
     *typedef uint32_t in_addr_t;
      struct in_addr
      {
        in_addr_t s_addr;
      }; 
     */
}

void tcp_header(tcphdr *tcp)
{
    printf("Source Port: %d \n",ntohs(tcp->th_sport));
    printf("Destination Port: %d \n",ntohs(tcp->th_dport));
    /*
     *
     * struct tcphdr
       {
            uint16_t th_sport;
       }
       1byte는 0x0
       2byte는 0x00
       2byte의 port값을 ntohs함수를 이용해
       ((port << 8 & 0xFF00) | port >> 8 & 0x00FF);
       인텔 리틀엔디안 때문에 3412로 저장되어있는 값을
       1234로 변환하여 클라이언트가 쉽게 볼 수 있도록 저장한다.
     */
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
    //패킷의 처음 주소값에 ethernet헤더의 길이를 더해
    //ip header의 처음 주소값으로 이동한다.
    ip_header_length = ((*ip_head)&0x0F);
    //ip header의 두번째 바이트는 헤더의 길이가
    //저장되어 있으므로 해당 길이만 뽑아낸다.
    ip_header_length = ip_header_length*4;
    //pointer형식을 맞춰주기 위해 4를 곱해준다

    u_char protocol = *(ip_head +9);
    //ip_head주소에 9를 더해주고 해당하는 값이
    //프로토콜이므로 저장해준다.

    tcp_head = packet + ethernet_header_length + ip_header_length;
    /*
    packet의 처음위치와 ethernet header의 처음주소값,
    ip header의 처음 주소값을 더해서 tcp header의 처음 주소값으로 이동한다.
    */

    tcp_header_length = ((*(tcp_head +12)) & 0xF0) >>4;
    //tcp header의 길이는 tcp header의 처음부터 12번째
    //지난 자리에 위치하므로 12를 더해 tcp hedaer의 길이 위치로 주소값을 옮긴다.
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
        /*
        while (byte_count++ < payload_length) {
            printf("%02X ",*temp_pointer);
            temp_pointer++;
            ten_count++;
            if(ten_count==10)
            {
                break;
            }
        }
        */
        printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",temp_pointer[0],
                temp_pointer[1],temp_pointer[2],temp_pointer[3],temp_pointer[4],
                temp_pointer[5],temp_pointer[6],temp_pointer[7],temp_pointer[8],
                temp_pointer[9]);

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
