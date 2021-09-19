#pragma once
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <pcap.h>

#define LIBNET_LIL_ENDIAN 1
#include "libnet.h"

#define IPV4 0x0800
#define TCP 0x06

#define GOOD 0
#define ERR_NOT_IP -1
#define ERR_NOT_TCP -2

#define STR_MAC_LEN 18
#define STR_PAYLOAD_LEN 9

using std::cout;
using std::endl;

const char* dev;
int count_pkt;

void usage()
{
	cout << "syntax: pcap-test <interface>"<< endl << "sample: sudo ./pcap-test eth0" << endl;
}

bool parse(int argc,char* argv[])
{
  if(argc!=2)
  {
    usage();
    return false;
  }
  dev = argv[1];
  return true;
}

void dump_ethernet(struct libnet_ethernet_hdr &ethernet,const u_char* packet,const int size)
{
	memcpy(&ethernet,packet,size);
	ethernet.ether_type = ntohs(ethernet.ether_type);
}

void dump_ip(struct libnet_ipv4_hdr &ip,const u_char* packet,const int size)
{
	memcpy(&ip,packet,size);
	ip.ip_len = ntohs(ip.ip_len);
	ip.ip_id = ntohs(ip.ip_id);
	ip.ip_off = ntohs(ip.ip_off);
	ip.ip_sum = ntohl(ip.ip_sum);
	//ip.ip_src.s_addr = ntohl(ip.ip_src.s_addr);
	//ip.ip_dst.s_addr = ntohl(ip.ip_dst.s_addr);
}

void dump_tcp(struct libnet_tcp_hdr &tcp,const u_char* packet,const int size)
{
	memcpy(&tcp,packet,size);
	tcp.th_sport = ntohs(tcp.th_sport);
	tcp.th_dport = ntohs(tcp.th_dport);
	tcp.th_seq = ntohl(tcp.th_seq);
	tcp.th_ack = ntohl(tcp.th_ack);
	tcp.th_win = ntohs(tcp.th_win);
	tcp.th_sum = ntohs(tcp.th_sum);
	tcp.th_urp = ntohs(tcp.th_urp);
}

int show_info(struct pcap_pkthdr* header,const u_char* packet)
{
  struct libnet_ethernet_hdr ethernet;
  struct libnet_ipv4_hdr ip;
  struct libnet_tcp_hdr tcp;

	const int ethernet_hdr_size = sizeof(struct libnet_ethernet_hdr);
	dump_ethernet(ethernet,packet,sizeof(struct libnet_ethernet_hdr));

	if(ethernet.ether_type == IPV4)
	{
		const int ip_hdr_size = (packet[ethernet_hdr_size] & 0x0f) << 2;

		dump_ip(ip,packet+ethernet_hdr_size,sizeof(struct libnet_ipv4_hdr));

		if(ip.ip_p == TCP)
		{
			const int tcp_hdr_size = (packet[ethernet_hdr_size+ip_hdr_size+12] & 0xf0) >> 2;
			dump_tcp(tcp,packet+ethernet_hdr_size+ip_hdr_size,sizeof(struct libnet_tcp_hdr));
			count_pkt++;

			char mac[STR_MAC_LEN] = {0};
			char payload[STR_PAYLOAD_LEN] = {0};

			cout << "===================================" << endl;
			cout << count_pkt << ' ' << "packet!" << endl;
			cout << "Ethernet Header" << endl;

			snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
			ethernet.ether_shost[0],ethernet.ether_shost[1],ethernet.ether_shost[2],
			ethernet.ether_shost[3],ethernet.ether_shost[4],ethernet.ether_shost[5]);
			cout << "[src mac] : " << mac << endl;

			snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
			ethernet.ether_dhost[0],ethernet.ether_dhost[1],ethernet.ether_dhost[2],
			ethernet.ether_dhost[3],ethernet.ether_dhost[4],ethernet.ether_dhost[5]);
			cout << "[dst mac] : " << mac << endl << endl;

			cout << "IP Header" << endl;
			cout << "[src ip] : " << inet_ntoa(ip.ip_src) << endl;
			cout << "[dst ip] : " << inet_ntoa(ip.ip_dst) << endl << endl;

			cout << "TCP Header" << endl;
			cout << "[src port] : "<< tcp.th_sport << endl;
			cout << "[dst port] : "<< tcp.th_dport << endl << endl;

			cout << "Payload(DATA) in HEX" << endl;
			int payload_len = ip.ip_len - ip_hdr_size - tcp_hdr_size;
			cout << "total payload length : " << payload_len << endl;

			for(int i=0;i<payload_len;i++)
			{
				if(i>=8) break;
				printf("%02X ",packet[ethernet_hdr_size+ip_hdr_size+tcp_hdr_size+i]);
			}
			cout << endl << endl;
		}
		else
			return ERR_NOT_TCP;
	}
	else
		return ERR_NOT_IP;

	return GOOD;
}
