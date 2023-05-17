//
// Created by russ on 23-4-26.
//
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/**
 * @param iface 网络接口名
 * @param filter 过滤规则
 * @compile gcc -o sniff_spoof sniff_spoof.c -lpcap
 * @usage ./sniff_spoof -i eth0 -f "icmp"
 * @description 该程序用于抓取指定网络接口的数据包，并对数据包进行分析
 */

#define PACKET_SIZE 4096
char pkt[PACKET_SIZE];
struct sockaddr_in dest;
int sock;

void handle_pkt(u_char* args ,const struct pcap_pkthdr* header,const u_char* packet);

int sniff(char* iface, char* filter){
    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_struct;
    bpf_u_int32 net,mask;
    /**
     * pcap_lookupnet 用于查找指定网络接口的网络号和掩码
     * 第一个参数表示网络接口
     * 第二个参数为网络号
     * 第三个参数为掩码
     * 第四个参数为错误缓冲区
     ***/
    pcap_lookupnet(iface,&net,&mask,err_buf);
    /**
     * pcap_opne_live创建一个sniff会话
     * 第一个参数表示网络接口名，可通过ifconfig命令获取
     * 第二个参数表示捕获数据包的最大长度，通常为65535
     * 第三个参数表示是否启用混杂模式 >0 表示启用
     * 第四个参数表示超时时间
     * 第五个参数为错误信息缓冲区
     */
    handle = pcap_open_live(iface,65535,1,1000,err_buf);
    if (handle == NULL){
        printf("failed to open sniff conversation\n");
        printf("error is %s\n",err_buf);
        return -1;
    }
    /**
     * pcap_compile 用于将bpf_program表示的过滤规则编译成可供内核使用的过滤器
     * 第一个参数为网络接口
     * 第二个参数为过滤器结构体
     * 第三个参数为过滤器规则
     * 第四个参数为是否开启优化，1表示开启，0表示关闭
     * 第五个参数为网络接口的掩码
     */
    pcap_compile(handle,&filter_struct,filter,1,mask);
    /**
     * pcap_setfilter 设置过滤器规则
     */
    pcap_setfilter(handle,&filter_struct);
    pcap_loop(handle,65535,handle_pkt,NULL);
    pcap_close(handle);
    return 0;
}

unsigned short checksum(unsigned short *addr,int len)
{
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;

    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，
    这个2字节数据的低字节为0，继续累加*/
    if( nleft==1)
    {
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

void handle_pkt(u_char* args ,const struct pcap_pkthdr* header,const u_char* packet){
    memset(pkt,0,PACKET_SIZE);
    struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct iphdr * fake_ip = (struct iphdr*)pkt;
    struct icmphdr * fake_icmp = (struct icmphdr*)(pkt + sizeof(struct iphdr));
    fake_ip->ihl = 5;
    fake_ip->version = 4;
    fake_ip->tos = 0;
    fake_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    fake_ip->frag_off = 0;
    fake_ip->id = htons(getpid());
    fake_ip->ttl = 64;
    fake_ip->protocol = IPPROTO_ICMP;
    fake_ip->check = 0;
    fake_ip->saddr = ip->daddr;
    fake_ip->daddr = ip->saddr;
    fake_ip->check = 0;
    fake_ip->check = checksum((unsigned short*)fake_ip,sizeof(struct iphdr));
    fake_icmp->type = ICMP_ECHO;
    fake_icmp->code = 0;
    fake_icmp->un.echo.id = icmp->un.echo.id;
    fake_icmp->un.echo.sequence = icmp->un.echo.sequence;
    fake_icmp->checksum = 0;
    fake_icmp->checksum = checksum((unsigned short*)fake_icmp,sizeof(struct icmphdr));
    dest.sin_addr.s_addr = fake_ip->daddr;
    size_t ret = sendto(sock,pkt,sizeof(struct iphdr) + sizeof(struct icmphdr),0,
            (struct sockaddr*)&dest,sizeof(dest));
    if (ret == -1) {
        printf("sendto error\n");
    }
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &fake_ip->saddr, ipstr, sizeof(ipstr));
    printf("from %s ", ipstr);
    inet_ntop(AF_INET, &fake_ip->daddr, ipstr, sizeof(ipstr));
    printf("to %s\n", ipstr);
}

void send_icmp(){
    struct iphdr* iph = (struct iphdr*)pkt;
    struct icmphdr* icmph = (struct icmphdr*)(pkt + sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    iph->id = htons(getpid());
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = inet_addr("1.2.3.4");
    iph->daddr = inet_addr("222.20.100.21");
    iph->check = 0;
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = 1;
    icmph->un.echo.sequence = 1;
    icmph->checksum = 0;
    icmph->checksum = checksum((unsigned short*)icmph,sizeof(struct icmphdr));
    dest.sin_addr.s_addr = iph->saddr;
    size_t ret = sendto(sock,pkt,sizeof(struct iphdr) + sizeof(struct icmphdr),0,(struct sockaddr*)&dest,sizeof(dest));
    if (ret == -1) {
        printf("sendto error\n");
        return;
    }
}

int main(int argc,char** argv){
    char iface[10];
    char filter[100];
    int opt = 0;
    while ((opt = getopt(argc,argv,"i:f:")) != -1){
        switch (opt)
        {
            case 'i':
                strcpy(iface,optarg);
                break;
            case 'f':
                strcpy(filter,optarg);
                break;
            default:
                printf("usage: ./sniff -i <iface> -f <filter>\n");
                exit(EXIT_FAILURE);
        }
    }
    dest.sin_family = AF_INET;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        printf("error create socket");
        return -1;
    }
    printf("iface is %s\n",iface);
    printf("filter is %s\n",filter);
    while (sniff(iface,filter) != 0);
//    return 0;
    send_icmp();
}