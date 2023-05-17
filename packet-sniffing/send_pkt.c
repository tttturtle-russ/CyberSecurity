//
// Created by russ on 23-4-26.
//

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

// 发送udp数据包
int send_udp_pkg(char* ip,int port,char* msg){
    // 创建一个套接字
    // 第一个参数表示通信协议簇，在linux环境下只能为AF_INET表示ipv4
    // 第二个参数type表示通信类型(tcp/udp...)
    // 第三个参数protocol表示协议，通常为0
    int sock = socket(AF_INET,SOCK_DGRAM,0);
    if (sock < 0){
        printf("failed to create socket\n");
        return -1;
    }
    // 此处不建议用malloc开辟内存
    struct sockaddr_in server;
    int length = sizeof(struct sockaddr_in);
    // htons将主机字节序转换为网络字节序 “Host to Network Short”
    server.sin_port = htons(port);
    // inet_addr 将点分十进制转换为 in_addr结构体
    server.sin_addr.s_addr = inet_addr(ip);
    // 设置协议族
    server.sin_family = AF_INET;
    // sendto 函数接收6个参数
    // 第一个参数fd为套接字
    // 第二，三个参数为数据以及数据长度
    // 第四个参数表示发送操作的可选标志，通常设置为0。
    // 第五个参数表示目标套接字的地址信息，为一个 sockaddr 结构体，通常将socketaddr_in 强转作为参数
    // 第六个参数表示表示目标套接字地址信息的长度，即为sockaddr_in的长度
    size_t ret = sendto(sock,msg,strlen(msg),0,(struct sockaddr*)&server,length);
    if (ret == -1){
        printf("send udp packet error!\n");
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}

//int main(){
//    send_udp_pkg("127.0.0.1",9091,"hello world!");
//}