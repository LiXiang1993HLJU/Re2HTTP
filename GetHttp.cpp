#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#define HAVE_REMOTE
#include "/usr/local/include/pcap.h"
#include "nids.h"
#include "zconf.h"
#include "zlib.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>




#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
#define BUF_SIZE 1024
#define SRV_PORT 53
typedef unsigned short U16;
const char srv_ip[] = "208.67.222.222";
u_int url_daddr = 0;

#define ETHERTYPE_IP 0x0800 /* ip protocol */
#define TCP_PROTOCAL 0x0600 /* tcp protocol */

#include "http_parser.h"


#include <assert.h>
#include <time.h>

static http_parser *parser;
std::string domain;
struct HTTP_MSG
{

    char filename[256];
    int  filenamelen;
    bool isgzip;
    bool isresq;
    bool isurl;
    char * url;
    void init()
    {
        memset(filename,0,256);
        isurl = false;
        isgzip = false;
        isresq = true;
        filenamelen = 0;
    };

};

static struct HTTP_MSG  Now_http;



int zcompress(Bytef *data, uLong ndata,
	Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;
	if (data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if (deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;
		c_stream.next_in = data;
		c_stream.avail_in = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata)
		{
			if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
		}
		if (c_stream.avail_in != 0) return c_stream.avail_in;
		for (;;) {
			if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
			if (err != Z_OK) return -1;
		}
		if (deflateEnd(&c_stream) != Z_OK) return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}
/* Compress gzip data */
int gzcompress(Bytef *data, uLong ndata,
	Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;
	if (data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			-MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
		c_stream.next_in = data;
		c_stream.avail_in = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata)
		{
			if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
		}
		if (c_stream.avail_in != 0) return c_stream.avail_in;
		for (;;) {
			if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
			if (err != Z_OK) return -1;
		}
		if (deflateEnd(&c_stream) != Z_OK) return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}
/* Uncompress data */
int zdecompress(Byte *zdata, uLong nzdata,
	Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream; /* decompression stream */
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if (inflateInit(&d_stream) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if (err != Z_OK) return -1;
	}
	if (inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}
/* HTTP gzip decompress */
int httpgzdecompress(Byte *zdata, uLong nzdata,
	Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = { 0 }; /* decompression stream */
	static char dummy_head[2] =
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if (inflateInit2(&d_stream, 47) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if (err != Z_OK)
		{
			if (err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*)dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if (inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}
/* Uncompress gzip data */
int gzdecompress(Byte *zdata, uLong nzdata,
	Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = { 0 }; /* decompression stream */
	static char dummy_head[2] =
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if (inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) return -1;
	//if(inflateInit2(&d_stream, 47) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if (err != Z_OK)
		{
			if (err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*)dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if (inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}



int on_message_begin(http_parser* _) {
  (void)_;
  printf("\n***MESSAGE BEGIN***\n\n");
  return 0;
}

int on_headers_complete(http_parser* _) {
  (void)_;
  
  printf("\n***HEADERS COMPLETE***\n\n");
  return 0;
}

int on_message_complete(http_parser* _) {
  (void)_;
  printf("\n***MESSAGE COMPLETE***\n\n");
  return 0;
}

int on_url(http_parser* _, const char* at, size_t length) {
  (void)_;
  printf("Url: %.*s\n", (int)length, at);
  memcpy(Now_http.filename,at,length);
  if(length == 1)
  {
    memcpy(Now_http.filename,"/index.html",11);
  }
  std::cout<<Now_http.filename<<std::endl;
  Now_http.filenamelen = length;
  return 0;
}

int on_header_field(http_parser* _, const char* at, size_t length) {
  (void)_;
  printf("%.*s:\t", (int)length, at);
  
 
  
  return 0;
}

int on_header_value(http_parser* _, const char* at, size_t length) {
  (void)_;

  printf("\t%.*s\n", (int)length, at);
  
   if(Now_http.isresq)
  {

  }else
  {
    if(strncmp(at,"gzip",length) == 0)
    {
      Now_http.isgzip = true;
    }
  }
  return 0;
}

int truelen = 0;
char buf[200000] = {0};
int on_body(http_parser* _, const char* at, size_t length) {
  (void)_;
   
  if(length == 8192)
  {
    memcpy(buf+truelen,at,length);
    truelen +=8192;
    return 0;
  }else{

   memcpy(buf+truelen,at,length);
    truelen += length;
  }
   


  uLong newlen = truelen;
 




  if(Now_http.isresq == false)
  {
      if(Now_http.isgzip)
      {
        char zbuf[200000] = {0};
        memcpy(zbuf,at,truelen);
        memset(buf,0,200000);
        newlen = 200000;
        httpgzdecompress((Bytef *)zbuf, truelen, (Bytef *)buf, &newlen);
      }
      //写入文件
      for(int i = 0 ;i < newlen; i++)
      {
        printf("%c",buf[i]);
      }


      //将buf 按照url写入文件　
      std::string spathname,sfilename;
      spathname =  domain;
      spathname = "mkdir -p \"./" + domain +"\"";
      sfilename = "./"+domain+Now_http.filename;

      system(spathname.c_str());
      
      std::string string_command;
      


      std::string stt(Now_http.filename);
      int i =0;
      for( i = stt.size()-1;i>=0;i--)
      {
          if(stt[i] == '/')
          {
            break;
          }
      }
      stt = stt.substr(0,i);



      string_command =  "mkdir -p \\" +domain  + stt;
      system(string_command.c_str());
      


      int fd;
    
      
  

      fd = open(sfilename.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      
      if(fd != -1)
      {

        write(fd, buf, newlen);
        close(fd);
      }else
      {
        std::cout<<sfilename<<std::endl;
      }


  }
  
  memset(buf,0,200000);
  truelen = 0;
  //printf("Body: %.*s\n", (int)length, at);
  return 0;
}

static http_parser_settings settings_null =  //http_parser的回调函数，需要获取HEADER后者BODY信息，可以在这里面处理。
  {.on_message_begin = on_message_begin
  ,.on_url = on_url
  ,.on_status = 0
  ,.on_header_field = on_header_field
  ,.on_header_value = on_header_value
  ,.on_headers_complete = on_headers_complete
  ,.on_body = on_body
  ,.on_message_complete = on_message_complete
  };





typedef struct _DNS_HDR
{
	U16 id;
	U16 tag;
	U16 numq;
	U16 numa;
	U16 numa1;
	U16 numa2;
}DNS_HDR;
typedef struct _DNS_QER
{
	U16 type;
	U16 classes;
}DNS_QER;


int url2domain(const std::string &url, std::string &domain, unsigned &port)
{

	int ret = -1;

	//使用迭代器拆分字符串
	std::regex reg_domain_port("/");  //按/符拆分字符串
	std::cregex_token_iterator itrBegin(url.c_str(), url.c_str() + url.size(), reg_domain_port, -1);
	std::cregex_token_iterator itrEnd;
	int i = 0;

	std::string domain_port;
	for (std::cregex_token_iterator itr = itrBegin; itr != itrEnd; ++itr)
	{
		i++;
		if (i == 3)
		{
			domain_port = *itr;
		}
	}

	if (domain_port.size() == 0)
	{
		domain_port = url;
	}

	//考虑带端口的情况
	std::regex reg_port(":");
	std::cregex_token_iterator itrBegin2(domain_port.c_str(), domain_port.c_str() + domain_port.size(), reg_port, -1);
	std::cregex_token_iterator itrEnd2;
	int j = 0;
	for (std::cregex_token_iterator itr = itrBegin2; itr != itrEnd2; ++itr) {
		j++;
		if (j == 1) {
			domain = *itr;
		}
		if (j == 2)
		{
			port = std::stold(*itr);
			//itoa(port,*itr,5);;
		}
	}

	if (domain.size() == 0)
	{
		domain = domain_port;
	}
	return ret;
}

char * adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}




int SegmentmessageRequ(const char * buf , int len,std::vector<int> &point)
{
	int num = 0;
	for (int i = 0; i < len - 10; i++)
	{
		if ((buf[i+0] == 'G'&& buf[i+1] == 'E'&&buf[i+2] == 'T') ||
			(buf[i+0] == 'P'&& buf[i+1] == 'O'&&buf[i+2] == 'S'&& buf[i+3] == 'T') ||
			(buf[i+0] == 'H'&& buf[i+1] == 'E'&&buf[i+2] == 'A'&& buf[i+3] == 'D') ||
			(buf[i+0] == 'D'&& buf[i+1] == 'E'&&buf[i+2] == 'L'&& buf[i+3] == 'E' &&buf[i+4] == 'T'&& buf[i+5] == 'E') ||
			(buf[i+0] == 'O'&& buf[i+1] == 'P'&&buf[i+2] == 'T'&& buf[i+3] == 'I' &&buf[i+4] == 'O'&& buf[i+5] == 'N') ||
			(buf[i+0] == 'T'&& buf[i+1] == 'R'&&buf[i+2] == 'A'&& buf[i+3] == 'C' &&buf[i+4] == 'E') ||
			(buf[i+0] == 'C'&& buf[i+1] == 'O'&&buf[i+2] == 'N'&& buf[i+3] == 'N' &&buf[i+4] == 'E'&& buf[i+5] == 'C'&& buf[i+5] == 'T')
			)
		{
			point.push_back(i);
			num++;
		}
	}
  point.push_back(len);
	return num+1;


}


int SegmentmessageResp(const char * buf, int len, std::vector<int> &point)
{
	//HTTP位置
	int num = 0;
	for (int i = 0 ; i < len-4; i++)
	{
		if (buf[i] == 'H' && buf[i+1] == 'T'&&buf[i+2] == 'T'&&buf[i+3] == 'P')
		{
			point.push_back(i);
			num++;
		}
	}
  point.push_back(len);
	return num+1;
}




void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
  

  if(a_tcp->addr.daddr!= url_daddr || a_tcp->addr.dest != 80)
  {
    //只关心这个ip　80端口上的通信
    return ;
  }
  //利用map储存不同端口的遍历进度

  
  size_t parsed;


  parser = (http_parser*)malloc(sizeof(http_parser));  //分配一个http_parser









  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      fprintf (stderr, "%s established\n", buf);
      //return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE||a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed normally
        //处理一个数据流　有可能包含多个数据
            struct half_stream *hlf;
        //处理
        
        


        hlf = &a_tcp->server; // analogical
        std::vector<int> Reqe , Resp;
        SegmentmessageRequ(hlf->data,hlf->count,Reqe);


        for(int i = 0 ; i < hlf->count ; i++)
        {
          printf("%c",hlf->data[i]);
        }



        hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                              // which will point to client side of conn
        //应答

        SegmentmessageResp(hlf->data,hlf->count,Resp);
        for(int i = 0 ; i < hlf->count ; i++)
        {
          printf("%c",hlf->data[i]);
        }
      

      //处理http一个循环

        //解析http　存入文件　


        if(Reqe.size()!=Resp.size())
        {
          printf("HTTP报文没有成对！\n");
          return;
        }else
        {
            
            for(int i = 0 ; i < Reqe.size()-1; i++)
            {
              
              Now_http.init();
              hlf = &a_tcp->server; // analogical
              http_parser_init(parser, HTTP_REQUEST);  //初始化parser为Request类型
              parsed = http_parser_execute(parser, &settings_null,  hlf->data+Reqe[i]  , Reqe[i+1] - Reqe[i]);  //执行解析过程

              Now_http.isresq = false;
              hlf = &a_tcp->client; // analogical  
              http_parser_init(parser, HTTP_RESPONSE);  //初始化parser为Response类型
              parsed = http_parser_execute(parser, &settings_null, hlf->data+Resp[i]  ,Resp[i+1] - Resp[i]);  //执行解析过程      


            }
        } 





     
      fprintf (stderr, "%s closing\n", buf);
   
      return;
    }


  if (a_tcp->nids_state == NIDS_DATA)
    {
 
    }
    //保存数据流
  nids_discard(a_tcp, 0);  
  return ;


}

int main ()
{
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;


  //(1)---------url 转换 Host  

              unsigned port;
      
              std::string url;
              //http://www.tuilixy.net/space-uid-42929.html
              printf("请输入url\n");
              std::cin>>url;
              url2domain(url, domain, port);
              if (domain.size() == 0)
              {
                printf("请输入正确url\n");
                return 0;
              }
              
              printf("%s\n",domain.c_str());
  //Host 通过 DNS 获得 IP

              int      servfd, clifd, len = 0, i;
              struct   sockaddr_in servaddr, addr;


              int      socklen = sizeof(servaddr);
              char     buf[BUF_SIZE];
              char     *p;
              DNS_HDR  *dnshdr = (DNS_HDR *)buf;
              DNS_QER  *dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR));


              if ((clifd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
              {
                printf(" create socket error!\n ");
                return -1;
              }

              bzero(&servaddr, sizeof(servaddr));
              servaddr.sin_family = AF_INET;
              inet_aton(srv_ip, &servaddr.sin_addr);
              servaddr.sin_port = htons(SRV_PORT);

              /*if (connect(clifd, (struct sockaddr *)&servaddr, socklen) < 0)
              {
              printf( " can't connect to %s!\n ", argv[ 1 ]);
              return -1;
              }*/
              memset(buf, 0, BUF_SIZE);
              dnshdr->id = (U16)1;
              dnshdr->tag = htons(0x0100);
              dnshdr->numq = htons(1);
              dnshdr->numa = 0;


              strcpy(buf + sizeof(DNS_HDR) + 1, domain.c_str());
              p = buf + sizeof(DNS_HDR) + 1; i = 0;
              while (p < (buf + sizeof(DNS_HDR) + 1 + domain.size()))
              {
                if (*p == '.')
                {
                  *(p - i - 1) = i;
                  i = 0;
                }
                else
                {
                  i++;
                }
                p++;
              }
              *(p - i - 1) = i;
              dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR) + 2 + domain.size());
              dnsqer->classes = htons(1);
              dnsqer->type = htons(1);


              len = sendto(clifd, buf, sizeof(DNS_HDR) + sizeof(DNS_QER) + domain.size() + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

              i = sizeof(struct sockaddr_in);
              len = recvfrom(clifd, buf, BUF_SIZE, 0, (struct sockaddr *)&servaddr, (socklen_t*)&i);

              if (len < 0)
              {
                printf("recv error\n");
                return -1;
              }
              if (dnshdr->numa == 0)
              {
                printf("ack error\n");
                return -1;
              }
              p = buf + len - 4;
              printf("%s ==> %u.%u.%u.%u\n", domain.c_str(), (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
              
              char  s[15] = {0};
              sprintf(s,"%u.%u.%u.%u", (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
              close(clifd);


  //通过监听指定IP 获得HTTP协议 
              

              in_addr t;
              inet_aton(s,&t);
              url_daddr = t.s_addr;













            //清除校验　－－>高版本网卡必须　nids能捕获tcp前提
            struct nids_chksum_ctl temp;
            temp.netaddr = 0;
            temp.mask = 0;
            temp.action = 1;
            nids_register_chksum_ctl(&temp,1);


              if (!nids_init ())
              {
                fprintf(stderr,"%s\n",nids_errbuf);
                return -1;
              }
              nids_register_tcp((void*)tcp_callback);
              nids_run ();
              return 0;
}
