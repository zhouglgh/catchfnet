#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>


void deal(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    static int count = 0;
    struct ether_header *eth_header;
    u_char *ptr;
    printf("Packet length:%d\n", hdr->len);
    printf("length of portion present: %d\n", hdr->caplen);

    eth_header = (struct ether_header*)packet;

    if(ntohs(eth_header->ether_type)!= ETHERTYPE_IP)
    {
        printf("not ehternet packet\n");
        return;
    }

    ptr = eth_header->ether_dhost;
    int i=0;
    printf("destination address(MAC):");

    while(i<ETHER_ADDR_LEN)
    {
        printf("%x",*ptr++);
        i++;
    }
    printf("\nsource address(MAC):");
    ptr = eth_header->ether_shost;
    i=0;
    while(i<ETHER_ADDR_LEN)
    {
        printf("%x",*ptr++);
        i++;
    }
    printf("\nfinish deal with %d packet\n",count);
    count++;
}

int main()
{
    pcap_t *sniffer_des;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *net_dev;
    bpf_u_int32 net,mask;
    struct bpf_program fp;
    const u_char *packet;
    struct pcap_pkthdr hdr;

    int ret;

    char filter[] = "port 8000";

    net_dev = pcap_lookupdev(errbuf);
    if(net_dev == NULL)
    {
        printf("get device error %s\n",errbuf);
    }
    net_dev = "ens192";
    if(pcap_lookupnet(net_dev,&net,&mask,errbuf) == -1)
    {
        printf("get net error:%s\n",errbuf);
        return 1;
    }
    sniffer_des = pcap_open_live(net_dev,BUFSIZ,1,1000,errbuf);
    if(sniffer_des == NULL)
    {
        printf("pcap_open_live%s\n",errbuf);
        return 1;
    }
    if(pcap_compile(sniffer_des, &fp, filter, 0, mask) == -1)
    {
        printf("pcap_compile error\n");
        return 1;
    }
    if(pcap_setfilter(sniffer_des, &fp) == -1)
    {
        printf("pcap_setfilter() error\n");
        return 1;
    }

    ret = pcap_loop(sniffer_des, 4, deal, NULL);

    if(ret == -1 || ret == -2)
    {
        printf("can not get the packet\n");
        return 1;
    }
    return 0;
}

