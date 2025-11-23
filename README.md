<aside>

💻 **PCAP Programming** : 

- C, C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램 작성
    - Ethernet Header: src, mac / dst mac
    - IP Header: src ip / dst ip
    - TCP Header: src port / dst port
    - Message 출력
- TCP protocol 만을 대상으로 진행

📎 PCAP Programming Github Link → https://github.com/dbfks/pcap_programming

</aside>

## 과제 개요

### ▣ 과제 목표

- C/C++ 기반의 PCAP API를 사용하여 TCP 패킷을 대상으로 분석하고, 헤더 정보를 출력하는 것을 목표로 프로그램을 작성하여야 한다.
- 해당 실습을 통해 패킷이 어떻게 구성되고, 네트워크에서 어떤 순서로 오가는지 확인하며 TCP 프로토콜에 대한 실무 감각을 키울 수 있다.

## Background

### ▣ PCAP이란?

- *PCAP(Packet Capture)*은 컴퓨터가 서로 주고받는 데이터를 실시간으로 확인하고, 누가 누구한테 어떤 내용의 데이터를 보냈는지 기록하고 분석할 수 있게 도와주는 도구이다.
- 컴퓨터 간의 통신은 패킷으로 이루어지며, PCAP는 이러한 *패킷을 실시간으로 가로채거나 저장하여 내용을 확인*할 수 있도록 한다.
- *모든 통신을 그대로 캡처해 기록* 하기 때문에, 사고 발생 시 PCAP 로그를 통해 침해 사고 분석이 가능하며, 실시간으로 이상 행위 탐지도 가능하다.
- 리눅스에서는 `libpcap`, 윈도우에서는 `WinPcap` 또는 `Npcap` 라이브러리를 통해 구현

### ▣ Ethernet / IP / TCP Header 구조

| Ethernet | IPv4 | TCP | HTTP |
| --- | --- | --- | --- |


<img width="546" height="246" alt="image" src="https://github.com/user-attachments/assets/0cc48c8e-2c9c-4e1d-9048-89f502e72c94" />

[https://blog.naver.com/sujunghan726/220315439853] Ethernet Header

- Source MAC Address(src mac) : 출발지 MAC 주소
- Destination MAC Address(dst mac) : 목적지 MAC 주소
- Type : 상위 프로토콜 식별


<img width="601" height="312" alt="image" src="https://github.com/user-attachments/assets/4b6745e2-d7e7-4956-b623-076eee5e4606" />

[https://blog.naver.com/sujunghan726/220315439853] IP Header

- Source IP Address(src ip) : 출발지 IP 주소
- Destination IP Address(dst ip) :  목적지 IP 주소
- Version: IP 버전
- Header Length : Header 길이
- Type of Service : 서비스 종류
- Total Length : 전체 패킷 길이 (헤더+데이터)
- Identification : 패킷 식별자
- Flag : 조각화 제어 플래그
- Fragment Offset : 조각의 위치 지정
- TTL : 생존 시간
- Protocol Type : 상위 계층 프로토콜
- Header Checksum : 헤더 오류 검출용 체크섬


<img width="613" height="266" alt="image" src="https://github.com/user-attachments/assets/3faba11a-b1fe-401e-9d47-2c6a44f04f50" />

- Source port(src port) : 출발지 포트 번호
- Destination port(dst port) : 목적지 포트 번호
- Sequence number : 시퀀스 번호
- Acknowledgement Number : 응답 번호
- TCP header length : Offset의 상위 4비트로 헤더 길이
- TCP flags : URG, SYN, ACK 등
- Window size : 수신 가능한 데이터 양
- Checksum : 오류 검출용 체크섬
- Urgent pointer : 긴급 데이터 처리

## 프로그램 설계

### 1) 환경 준비

- libpcap 설치 및 C 컴파일러 준비
    
    ```bash
    sudo apt install libpcap-dev
    ```
    

### 2) 프로그램 구조 설계

step 1: 네트워크 디바이스 열기

step 2: TCP 대상으로만 필터 적용

step 3: 패킷 캡처 시작

3.1. Ethernet/IP/TCP 헤더 파싱

3.2. 각 필드 출력(src/dst mac, ip, port, message)

step 4: 종료

### 3) Ethernet Header 구조체

```c
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};
```

### 4) IP Header 구조체

```c
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
```

### 5) TCP Header 구조체

```c
/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};
```

## 코드 설명

```c
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// 3.1. Ethernet/IP/TCP 헤더 파싱
	// 3.2 각 필드 출력(src/dst mac, ip, port, message)
}

int main() {
	pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  // 1. pcap_open_live 함수로 NIC 열기
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
	  fprintf(stderr, "Error!:%s\n", errbuf);
	  return 1;
  }
  
	// 2. TCP 대상으로만 필터 적용
	struct bpf_program fp;
  char filter_exp[] = "tcp"; //필터 문자열 선언
  bpf_u_int32 net;
  pcap_compile(handle, &fp, filter_exp, 0, net); 
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
	
	// 3. 패킷 캡처 시작
	pcap_loop(handle, 0, got_packet, NULL);
	
	// 4. 종료
	pcap_close(handle);
	return 0;
}
```

### step 1. pcap_open_live 함수로 NIC 열기

<aside>

`pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf);`

- 네트워크 디바이스를 열고 패킷 캡처 시작
- device : 캡처할 디바이스 이름
- snaplen : 한 패킷에서 읽는 최대 바이트 수
- promisc : 1이면 promiscuous mode로 모든 패킷 캡처, 0이면 자기 패킷만 캡처
- to_ms : 패킷 대기 시간
- ebuf : 에러 메시지 버퍼
</aside>

### step 2. TCP 대상으로만 필터 적용

<aside>

`struct bpf_program fp;`

- PCAP 필터를 설정할 때 사용하는 구조체로, `pcap.h`에 정의됨
- `pcap_compile()` 함수가 필터 표현식을 BPF(Bytecode Filter) 포맷으로 컴파일한 결과를 담는 곳
- `pcap_setfilter()`로 적용하면, 패킷 캡처 시 조건에 맞는 패킷만 걸러서 got_packet()에 전달
</aside>

### step 3. 패킷 캡처 시작

<aside>

`pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);`

- 반복하여 패킷을 읽고, 콜백 함수로 처리하는 함수
- p : pcap_open_live()로 받은 핸들
- cnt : 읽을 패킷 수 (-1일 경우 무한 루프)
- callback : 패킷이 수신될 때마다 호출되는 함수
- user : 콜백 함수에 전달할 사용자 정의 데이터
</aside>

### step 3.1. Ethernet/IP/TCP 헤더 파싱

```c
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet; // 이더넷 헤더 파싱
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // IP 헤더 파싱
    
    //TCP 패킷인 경우 처리
    if (ip->iph_protocol == IPPROTO_TCP) {
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4)); // TCP 헤더 파싱
        
        // 이더넷 MAC 주소 출력
        printf("Ethernet: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Ethernet: Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

				// IP 주소 출력
        printf("IP: Src: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("IP: Dst: %s\n", inet_ntoa(ip->iph_destip));
				// TCP 포트 출력
        printf("TCP: Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("TCP: Dst Port: %d\n", ntohs(tcp->tcp_dport));

				// payload 계산, 출력
        int ip_header_len = ip->iph_ihl * 4;
        int tcp_header_len = TH_OFF(tcp) * 4;
        const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

        printf("Message: ");
        for (int i = 0; i < payload_len && i < 512; i++) {
            putchar(payload[i]);
        }
        printf("\n");
    }
} 

```

<aside>

`struct ethheader *eth = (struct ethheader *)packet;`

- 바이트 배열 상태인 `packet`
- `packet`의 맨 앞은 Ethernet 헤더이므로
- `ethheader` 구조체로 읽어옴
</aside>

- IP 헤더는 Ethernet 헤더 다음에 오므로 `packet + sizeof(struct ethheader)`
- IP 헤더의 시작 주소로 포인터 이동하여 ipheader 구조체로 파싱
- 그 다음은 Ethernet header + IP header 더한 위치로 이동
- TCP 헤더의 시작 주소로 포인터 이동하여 파싱

<aside>

`inet_ntoa()`

- IP 주소를 문자열로 바꿔주는 함수

`ntohs()`

- 네트워크 바이트 순서(빅엔디안)을 호스트 바이트 순서로 변환해주는 함수
</aside>

<aside>

- Payload(Message) 위치는 Ethernet 헤더 길이에 ip_header_len과 tcp_header_len을 더하여 packet 포인터를 이동하면 구할 수 있음
- Payload 길이는 전체 캡쳐 길이에서 헤더 길이를 빼면 구할 수 있음
</aside>

## 실행 결과
<img width="803" height="672" alt="image" src="https://github.com/user-attachments/assets/203eb953-e2c3-40ac-96ac-8d2decb8e4d8" />



<aside>

✅ 참고 코드

https://github.com/pwnhyo/network_security_codes/blob/main/Sniffing_Spoofing/C_sniff/sniff_improved.c

https://github.com/pwnhyo/network_security_codes/blob/main/Sniffing_Spoofing/C_spoof/myheader.h

</aside>
