一个网络课程的作业，利用libpcap从网卡上抓包还原网页的过程。不定期优化更新。
内容介绍:
        利用一个DNS服务器解析URL的目的IP
        只截取目的IP的80端口通信的HTTP流
        通过NIDS直接获取TCP流
        当TCP流断开的时候(收到FIN或RET分节)，切割TCP成为HTTP报文(HTTP1.1的多个HTTP报文共用1个TCP流)。
        
        
编译依赖的库 nids,pcap,http_parser,zlib;
g++ -std=c++1 GetHTTP.cpp -lnids -lpcap -lnet -lglib-2.0 -lgthread-2.0 -lhttp_parser -lz -o GetHTTP.out
