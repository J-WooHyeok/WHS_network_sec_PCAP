#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
  unsigned short int tcp_sport; // Source port
  unsigned short int tcp_dport; // Destination port
  unsigned char tcp_ihl:4; // TCP header length
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    struct tcpheader * tcp = (struct tcpheader *)
	    		     (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

    /* detemine protocol */
    switch(ip->iph_protocol) {
	    case IPPROTO_TCP:
		    printf("   Protocol : TCP\n");
		    break;
	    case IPPROTO_UDP:
		    printf("   Protocol : UDP\n");
		    break;
	    case IPPROTO_ICMP:
		    printf("   Protocol : ICMP\n");
		    break;
	    default:
		    printf("   Protocol : others\n");
		    break;
    }


    // Ethernet Header 출력
    // src는 ether_shost에, dst는 ether_dhost에 저장되어 있음
    printf("Ethernet Header\n");
    printf("    src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
		    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("    dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
		    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP Header 출력
    // src는 iph_sourceip에, dst는 iph_destip에 저장되어 있음
    // ip주소를 string 형식으로 출력하기 위해 ntoa() 함수 사용
    printf("IP Header\n");
    printf("     src ip : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("     dst ip : %s\n", inet_ntoa(ip->iph_destip));

    // TCP Header 출력
    // src는 tcp_sport에, dst는 tcp_dport에 저장되어 있음
    // 빅 엔디언 방식의 데이터를 리틀 엔디언 방식으로 변환하기 위해 ntohs 사용
    printf("TCP Header\n");
    printf("   src port : %d\n", ntohs(tcp->tcp_sport));
    printf("   dst port : %d\n", ntohs(tcp->tcp_dport));
    
    /* 메시지 출력하기 */

    // IP 헤더 크기
    // 각 4바이트 이므로 실제 크기는 길이 * 4
    int ip_header_len = ip->iph_ihl * 4;
    // TCP 헤더 크기
    // 각 4바이트 이므로 실제 크기는 길이 * 4
    int tcp_header_len = tcp->tcp_ihl * 4;
    // 전체 헤더 크기
    // Ethernet 헤더 크기(14바이트) + IP 헤더 크기 + TCP 헤더 크기
    int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    // 메시지 시작지점 계산
    int message_size = header->caplen - total_header_size;
    // 메시지 출력 (20바이트만)
    if (message_size > 0) {
	    int print_size = message_size;
	    printf("MESSAGE (%d bytes)\n", message_size);

	    // 메시지가 20바이트보다 큰 경우, 20바이트 까지만 출력
	    if (message_size > 20) {
		    print_size = 20;
	    }

	    // print_size만큼 메시지 출력
	    for(int i = 0; i < print_size; i++) {
		    // 읽을 수 있는 문자만 출력
		    if (isprint(packet[print_size + i])) {
		            printf("%c", packet[total_header_size + i]);
		    }
		    else {
			    printf("사람이 읽지 못하는 언어입니다.");
		    	    break;
		    }
	    }
	    printf("\n");
    }
    printf("================================================\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

