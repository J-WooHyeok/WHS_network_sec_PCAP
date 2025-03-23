# 🔐 WHS_network_sec_PCAP
**[WHS][PCAP Programming]18반 장우혁(2212)**   
이 프로젝트는 `pcap` 라이브러리를 사용하여 C로 구현된 간단한 패킷 스니퍼(sniffer) 입니다.   
네트워크에서 TCP 패킷을 캡처하고 Ethernet, IP, TCP 헤더 정보를 출력하며, 메시지 내용 일부를 표시합니다.

## 📋 주요 기능
- `pcap`을 사용한 네트워크 패킷 캡처
- Ethernet, IP, TCP 헤더 정보 추출 및 출력
- 메시지 데이터 일부 출력 (20바이트 제한)

## 💻 환경 세팅
- VirtureBox
- Ubuntu 20.04

## 🎓 코드 설명
### ⭐️ 헤더
- `ethheader` : 이더넷의 헤더로 출발지와 목적지 주소, 프로토콜 정보를 저장합니다.
- `ipheader` : IP의 헤더로 헤더의 길이, 패킷의 길이, 프로토콜 정보, 출발지와 목적지 주소 등의 정보를 저장합니다.
- `tcpheader` : TCP의 헤더로 출발지와 목적지 주소, TCP 헤더의 길이 정보를 저장합니다.

### ⭐️ 함수
- `got_packet` : 패킷이 캡처되었을때 패킷의 프로토콜과 이더넷, IP, TCP의 헤더의 정보 그리고 메시지 내용의 일부를 출력하는 함수입니다.
  - 현재 캡처된 프로토콜의 종류를 출력합니다.
  - Ethernet의 출발지와 목적지 주소를 출력합니다.
  - IP의 출발지와 목적지 주소를 출력합니다.
  - TCP의 출발지와 목적지 주소를 출력합니다.
  - 통신에서 주고받은 메시지 내용의 일부를 출력합니다.

### ⭐️ 추가한 코드 & 설명
```C
struct tcpheader * tcp = (struct tcpheader *)
                         (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
```
- `tcp`는 TCP헤더의 첫 번째 바이트를 가리키는 포인터로, TCP의 출발지와 목적지 주소, 헤더 크기정보를 가져오기 위해 추가했습니다.   
- TCP 헤더의 첫 번째 바이트는 IP 헤더가 끝난 뒤 이므로 IP 헤더의 길이를 구하고 그 값에 4를 곱해 IP 헤더의 전체 크기를 구했습니다.   
- `packet + sizeof(struct ethheader)`는 IP 헤더 시작 주소이고, `+ ip->iph_ihl * 4` 즉 IP 헤더 크기만큼 이동하여 TCP 헤더 시작 주소를 구했습니다.   
   
    
```C
printf("Ethernet Header\n");
printf("    src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
		    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
printf("    dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
		    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
```
- Ethernet헤더에서 출발지와 목적지의 MAC 주소를 출력하기 위해 추가했습니다.   
- `%02X`는 2자리 16진수 대문자로 출력이 됩니다.(00, 8A, CE, ...)   
- `ether_shost`와 `ether_dhost`는 각각 Source MAC 주소, Destination MAC 주소 즉, 출발지와 목적지 주소를 저장하고 있는 배열입니다. (ethheader 헤더 참고)   
   
   
```C
printf("IP Header\n");
printf("     src ip : %s\n", inet_ntoa(ip->iph_sourceip));
printf("     dst ip : %s\n", inet_ntoa(ip->iph_destip));

printf("TCP Header\n");
printf("   src port : %d\n", ntohs(tcp->tcp_sport));
printf("   dst port : %d\n", ntohs(tcp->tcp_dport));
```
- IP와 TCP 헤더에서 출발지와 목적지의 주소를 출력하기 위해 추가했습니다.   
- `inet_ntoa()` 함수는 빅 엔디안으로 저장된 IP 주소를 사람이 읽을 수 있는 문자열로 변환해줍니다.   
- `ip->iph_sourceip`와 `ip->iph_destip`는 각각 출발지와 목적지 IP주소를 저장하고 있습니다.   
- `ntohs()` 함수는 빅 엔디안을 리틀 엔디안으로 변환해줍니다.   
- `tcp->tcp_sport`와 `tcp->tcp_dport`는 각각 출발지와 목적지 포트번호를 저장하고 있습니다.   
   
   
```C
int ip_header_len = ip->iph_ihl * 4;
int tcp_header_len = tcp->tcp_ihl * 4;
int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
int message_size = header->caplen - total_header_size;

if (message_size > 0) {
  int print_size = message_size;
  printf("MESSAGE (%d bytes)\n", message_size);

  if (message_size > 20) {
    print_size = 20;
  }

  for(int i = 0; i < print_size; i++) {
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
```
- 메시지를 간단하게 출력하기 위해 추가했습니다.
- `ip->iph_ihl * 4`와 `tcp->tcp_ihl * 4`는 IP와 TCP 헤더의 크기를 계산한 코드입니다. 둘 다 4바이트 단위로 저장되므로 4를 곱했습니다.   
- `sizeof(struct ethheader)` 이 함수를 통해 이더넷 헤더의 크기를 구할수 있습니다.   
- 전체 헤더 크기는 위와 같이 **이더넷 헤더 크기 + IP 헤더 크기 + TCP 헤더 크기** 로 구할 수 있습니다.   
- `header->caplen`으로 캡처된 패킷의 총 크기를 불러와 전체 헤더 크기를 빼면 메시지의 크기를 구할 수 있습니다.   
- `if (message_size > 0)`는 메시지가 없는 경우도 있기 때문에 메시지가 있는 경우에만 출력하도록 했습니다.   
- `message_size > 20`은 "간단한" 메시지를 표시하기 위해 20바이트로 크기를 제한하는 코드입니다.   
- `isprint()` 함수를 사용하여 출력 가능한 아스키코드 문자인지 확인합니다.   
   
### 🚨 문제점
- 여러번 시도를 해보았지만 사람이 읽을 수 있는 메시지가 나오지 않았습니다.






