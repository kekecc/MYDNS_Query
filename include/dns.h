#ifndef _DNS_H_
#define _DNS_H_

#include <cstddef>
#include <ios>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include <string>
//网络通信
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

        typedef struct {
        //报文首部字段
        //1.事务id
        unsigned short Trid; //16位

        //2.标志 flags
        unsigned char RD : 1; //期望递归
        unsigned char TC : 1; //truncated 1表示被截断
        unsigned char AA : 1; //授权 1表示是名称服务器为权威服务器
        unsigned char Opcode : 4; //操作码 0表示标准查询 1表示反向查询 2表示服务器状态请求
        unsigned char QR : 1; //response 0表示相应

        unsigned char rcode : 4; //返回码
        unsigned char CD : 1; //check disabel
        unsigned char AD : 1; //认证数据
        unsigned char Z : 1; //只设为0
        unsigned char RA : 1; //只出现在服务器 1表示支持递归查询

        unsigned short Questions;
        unsigned short AnswerRRs;
        unsigned short AuthorityRRs;
        unsigned short AdditionalRRs;
      }Header;

       typedef struct {
        unsigned short Qtype;
        unsigned short Qclass;
      }Question;

       typedef struct{
        //查询问题部分 查询名称 查询类型 查询类
        unsigned char* Qname;
        unsigned short Qtype;
        unsigned short Qclass;
      }Query;

      typedef struct {
        unsigned short Rtype;
        unsigned short Rclass;
        unsigned int Ttl;
        unsigned short Rlen;
      }Resource;
      
      typedef struct {
        //资源记录部分 只出现在响应包
        unsigned char* Rname;
        unsigned short Rtype;
        unsigned short Rclass;
        unsigned int Ttl;
        unsigned short Rlen;
        unsigned char* Rdata;
        string ip;
      }Resource_Record;

      struct DNS_Query {
        Header DNS_Header;
        Query DNS_Query;
        Resource_Record *DNS_Answer;
        Resource_Record *DNS_Authority;
        Resource_Record *DNS_Additional;
      };
class DNS_Message {
    private:
      const int PORT = 53;
      string DNS_Server = "1.1.1.1"; //默认使用的dns服务器
    public:
      int trace = 0;
      struct DNS_Query MyDNS;
      DNS_Message(int trace = 0):trace(trace) {
        MyDNS.DNS_Query.Qname = nullptr;
        MyDNS.DNS_Answer = nullptr;
        MyDNS.DNS_Header.AnswerRRs = 0;
        MyDNS.DNS_Authority = nullptr;
        MyDNS.DNS_Header.AuthorityRRs = 0;
        MyDNS.DNS_Additional = nullptr;
        MyDNS.DNS_Header.AdditionalRRs = 0;
      } 
      ~DNS_Message() {};
      
      int GetIP(const string host, string nameserver, int type); //默认 A类型
      int GetIPbyNS(const string host, string nameserver);//默认 NS类型
      int HostToFormat(string host, unsigned char* format);
      int FormatToHost(unsigned char* format);
      int ParseDNSBuffer(const unsigned char* buffer);
      void PrintResult(Resource_Record* rs);
      unsigned int RecordOneResource(unsigned char* buf, const unsigned char* buffer, Resource_Record* rr);
      unsigned int RecordONeName(int flag, unsigned char* buf, const unsigned char* buffer, Resource_Record* rr);
      void PrintTheAnswer();
};


#endif