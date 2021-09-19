#include "pcap-test.h"

int main(int argc,char* argv[])
{
  if (!parse(argc, argv))
		return -1;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

  if(pcap == NULL)
  {
    fprintf(stderr, "pcap_open_live(%s) return null - %s\n",dev,errbuf);
    return -1;
  }

  while(true)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(pcap, &header, &packet);

    if(res == 0) continue;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
			cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(pcap)<<')'<<endl;
			break;
		}
    int ret = show_info(header,packet);
    if (ret == ERR_NOT_TCP)
    {
      cout << "NOT TCP!" << endl;
    }
    else if(ret == ERR_NOT_IP)
    {
      cout << "NOT IP!" << endl;
    }
    else
    {
      cout << "well done!" << endl;
    }
  }

  pcap_close(pcap);
  return 0;
}
