#include "/home/kk/Desktop/socket/DNS_Query/include/dns.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>

int DNS_Message::HostToFormat(string host, unsigned char *format) {
    //将域名转换为标准形式 www.baidu.com -> \3www\5baidu\3com
    if (host == "") {
        return -1;
    }
    int temp = 0;
    host.append("."); //结束标志
    unsigned char* name = (unsigned char*)host.c_str();
    for (int i = 0; i < strlen((char *)name); i++) {
        if (name[i] == '.') {
            *format ++ = i - temp;
            while (temp < i) {
                *format++ = host[temp];
                temp ++;
            }
            temp = i + 1; //bug
        }
    }
    *format = '\0';
    return 0;
}

int DNS_Message::FormatToHost(unsigned char *format) {
    //将标准形式转换为常见域名 \3www\5baidu\3com -> www.baidu.com
    unsigned int p;
    int i;
    for (i = 0; i < (int)strlen((const char *)format); i++) {
        p = format[i];
        for (int j = 0; j < p; j++) {
            format[i] = format[i + 1];
            i++;
        }
        format[i] = '.';
    }
    format[i - 1] = '\0';
    return 0;
}

int DNS_Message::GetIP(const string host, string nameserver, int type) {
    int client_fd; //socket 连接
    struct sockaddr_in destination;
    Header* header; //头部
    Question* question;//问题
    unsigned char* Qname; //问题名
    unsigned char* buffer;//传信息
    unsigned char* l;
    unsigned int deslen;
    unsigned int bufferlen = 0;
    
    if (trace == 1) {
        cout << "hostname :" << host << " " << "parsed by " << nameserver << endl;
    }
    
    buffer = new unsigned char[90024];
    if (buffer == nullptr) {
        return -1;
    }

    if (trace == 1) {
        cout << "sending request message.." << endl; 
    }
    //获取socket
    client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    destination.sin_addr.s_addr = inet_addr(nameserver.c_str());
    destination.sin_port = htons(PORT);
    destination.sin_family = AF_INET;
    header = (Header*)buffer;
    
    //初始化header
    header->Trid = (unsigned short)htons(10); //随便给出
    header->QR = 0;
    header->Opcode = 0;
    header->AA = 0;
    header->TC = 0;
    header->RD = 1;
    header->RA = 0;
    header->Z = 0;
    header->AD = 0;
    header->CD = 0;
    header->rcode = 0;
    header->Questions = htons(1);
    header->AnswerRRs = 0;
    header->AuthorityRRs = 0;
    header->AdditionalRRs = 0;
    bufferlen += sizeof(Header); //截断 到这里前面都是header部分
    
    Qname = buffer + bufferlen; //获取在buffer中属于问题名的部分
    HostToFormat(host, Qname); //把标准格式储存在Qname
    cout << Qname << endl;
    bufferlen += (strlen((char*) Qname) + 1); 

    question = (Question*)(buffer + bufferlen); //buffer中属于问题部分的字段
    question->Qtype = htons(type); //表示A记录 取ip地址
    question->Qclass = htons(1); //internet数据
    bufferlen += sizeof(Question); 
    
    //connect(client_fd, (struct sockaddr*)&destination, sizeof(destination));
    if (trace == 1) {
        cout << "send message lens = " << bufferlen << "to server" << endl;
    }
    //发送数据
    if (sendto(client_fd, (char *)buffer, bufferlen, 0, (struct sockaddr *)&destination, sizeof(destination)) < 0) {
        return -1;
    }

    if (trace == 1) {
        cout << "send message successfully" << endl;
    }
    deslen = sizeof(destination);
    //获取返回数据
    ssize_t temp = recvfrom(client_fd, (char *)buffer, 90024, 0, (struct sockaddr*)&destination, &deslen);
    if (temp < 0) {
        return -1;
    }
    
    //Header* newhead = (Header*)buffer;
    //cout << ntohs(newhead->Trid) << endl;
    if (trace == 1) {
        cout << "get message successfully!" << endl;
    }

    //解析数据到结构体中
    ParseDNSBuffer(buffer);

    return 0;
}

int DNS_Message::ParseDNSBuffer(const unsigned char* buffer) {
    Header* header = nullptr;
    Question* question = nullptr;
    Resource* resource = nullptr;
    unsigned char* Qname;
    unsigned char* buf; //用来将某些部分拿出来作为参数
    unsigned int index; //确定每一部分解析完成的时候每次位置
    unsigned int Qu_number, Ad_number, Au_number, An_number; //响应中各部分的多少

    //解析header
    header = (Header*)buffer;
    MyDNS.DNS_Header = *header;
    MyDNS.DNS_Header.Trid = ntohs(header->Trid);
    An_number = ntohs(header->AnswerRRs);
    MyDNS.DNS_Header.AnswerRRs = An_number;
    Au_number = ntohs(header->AuthorityRRs);
    MyDNS.DNS_Header.AuthorityRRs = Au_number;
    Ad_number = ntohs(header->AdditionalRRs);
    MyDNS.DNS_Header.AdditionalRRs = Ad_number;
    Qu_number = ntohs(header->Questions);
    MyDNS.DNS_Header.Questions = Qu_number;

    index = sizeof(Header);
    
    //获取问题区域的第一部分 名字
    Qname = (unsigned char*)(buffer + index);
    int Qname_len = strlen((char *)Qname) + 1;
    MyDNS.DNS_Query.Qname = new unsigned char[Qname_len];
    strcpy((char *)MyDNS.DNS_Query.Qname, (char *)Qname); //复制过去
    FormatToHost(MyDNS.DNS_Query.Qname);

    index += Qname_len;
    
    //获取问题区域的其他部分
    question = (Question *)(buffer + index);
    MyDNS.DNS_Query.Qtype = ntohs(question->Qtype);
    MyDNS.DNS_Query.Qclass = ntohs(question->Qclass);

    index += sizeof(Question);
    
    buf = (unsigned char*)(buffer + index);
    
    //获取回答
    MyDNS.DNS_Answer = new Resource_Record[An_number]; //有这么多个回答
    if (MyDNS.DNS_Answer == nullptr) {
        return -1;
    }
    for (int i = 0; i < An_number; i++) {
        buf += RecordOneResource(buf, buffer, &MyDNS.DNS_Answer[i]);
        //cout << MyDNS.DNS_Answer[i].Rlen << endl;
        //cout << MyDNS.DNS_Answer[i].Rtype << endl;
        //if (MyDNS.DNS_Answer[i].Rtype == 1) {
        //cout << MyDNS.DNS_Answer->ip << endl;
        //} else {
       // cout << MyDNS.DNS_Answer->Rdata << endl;
        //}
    }
    
    //获取权威信息
    MyDNS.DNS_Authority = new Resource_Record[Au_number];
    if (MyDNS.DNS_Authority == nullptr) {
        return -1;
    }
    for (int i = 0; i < Au_number; i++) {
        buf += RecordOneResource(buf, buffer, &MyDNS.DNS_Authority[i]);
    }

    //获取额外的信息
    MyDNS.DNS_Additional = new Resource_Record[Ad_number];
    if (MyDNS.DNS_Additional == nullptr) {
        return -1;
    }
    for (int i = 0; i < Ad_number; i++) {
        buf += RecordOneResource(buf, buffer, &MyDNS.DNS_Additional[i]);
    }
    

    //这样 所有的东西可以通过字段轻松获取
    return 0;
}


//解析资源的函数
unsigned int DNS_Message::RecordONeName(int flag, unsigned char *buf, const unsigned char *buffer, Resource_Record *rr) {
    unsigned char* Rname = new unsigned char[256];
    Rname[0] = '\0';
    unsigned char* temp = buf;
    unsigned off; 
    int ans = 0;
    unsigned int number = 0; //返回的数据
    
    int i = 0;
    while (temp != nullptr && (*temp) != 0) {
        if (0xc0 == ((*temp) & 0xc0)) {
            off = (((*temp) & (~0xc0)) << 8) + *(temp + 1);
            temp = (unsigned char *)(buffer + off - 1);
            ans = 1;
        } else {
            Rname[i++] = *temp;
            //cout << *temp << endl;
        }
        temp ++;
        if (ans == 0) {
            number ++;
        }
    }
    if (ans == 1) {
        number ++;
    }
    number ++;
    Rname[i] = '\0';
    //cout << Rname << endl;
    FormatToHost(Rname);
    
    //cout << Rname << endl;


    if (flag == 0) {
        rr->Rname = Rname;
        //cout << "zhe" << endl;
    } else {
        rr->Rdata = Rname;
        ///cout << "na " << endl;
    }

    return number;
}


unsigned int DNS_Message::RecordOneResource(unsigned char *buf, const unsigned char *buffer, Resource_Record *rr) {
    unsigned int index; //确定位置
    Resource* resource;
    unsigned char* temp = buf;
    unsigned char* n = new unsigned char[256];
    if (temp == nullptr) {
        return -1;
    }
    
    index = RecordONeName(0, temp, buffer, rr);

    temp = buf + index;

    resource = (Resource*)temp;
    rr->Rtype = ntohs(resource->Rtype);
    rr->Rclass = ntohs(resource->Rclass);
    rr->Ttl = ntohl(resource->Ttl);
    rr->Rlen = ntohs(resource->Rlen);
    
    index += sizeof(Resource) - 2;
    temp = buf + index;
    int i = 0;

    if (rr->Rtype == 1) {
        rr->Rdata = new unsigned char[rr->Rlen];
        unsigned char* p = new unsigned char[rr->Rlen];
        stringstream res;
        p = temp;

        for (i = 0; i < 4; i++) {
        if (i != 0) res << ".";
        res << static_cast<int>(p[i]);
        }
        for (i = 0; i < rr->Rlen; i++) {
            rr->Rdata[i] = temp[i];
        }
        rr->Rdata[rr->Rlen] = '\0';
        rr->ip = res.str();
        //cout << res.str() << endl;
        //cout << rr->ip << endl;
        //rr->Rdata[rr->Rlen] = '\0';
        //cout << ntohl((unsigned long)rr->Rdata) << endl;
        //cout << rr->Rdata << endl;
        index += rr->Rlen;
        temp = buf + index; 
        
    } else {
        RecordONeName(1, temp, buffer, rr);
        index += rr->Rlen;
        temp = buf + index;
    }
    return index;
}


void DNS_Message::PrintTheAnswer() {
    
    for (int i = 0; i < MyDNS.DNS_Header.AnswerRRs; i++) {
        cout << endl;
        cout << "Answer:" << i + 1 << endl;
        cout << "name :" << MyDNS.DNS_Answer[i].Rname << endl;
        cout << "type :" << MyDNS.DNS_Answer[i].Rtype << endl;
        cout << "class :" << MyDNS.DNS_Answer[i].Rclass << endl;
        cout << "len :" << MyDNS.DNS_Answer[i].Rlen << endl;
        cout << "ttl :" << MyDNS.DNS_Answer[i].Ttl << endl;
        cout << "data :" ;
        if (MyDNS.DNS_Answer[i].Rtype == 1) {
            for (int j = 0; j < MyDNS.DNS_Answer[i].Rlen - 1; j++) {
                cout << (int)(MyDNS.DNS_Answer[i].Rdata[j]) << ".";
            }
            cout << (int)(MyDNS.DNS_Answer[i].Rdata[MyDNS.DNS_Answer[i].Rlen - 1]) << endl;
        } else {
            cout << MyDNS.DNS_Answer[i].Rdata << endl;
        }   
    }

    for (int i = 0; i < MyDNS.DNS_Header.AdditionalRRs; i++) {
        cout << endl;
        cout << "Additional:" << i + 1 << endl; 
        cout << "name :" << MyDNS.DNS_Additional[i].Rname << endl;
        cout << "type :" << MyDNS.DNS_Additional[i].Rtype << endl;
        cout << "class :" << MyDNS.DNS_Additional[i].Rclass << endl;
        cout << "len :" << MyDNS.DNS_Additional[i].Rlen << endl;
        cout << "ttl :" << MyDNS.DNS_Additional[i].Ttl << endl;
        cout << "data :" ;
        if (MyDNS.DNS_Additional[i].Rtype == 1) {
            for (int j = 0; j < MyDNS.DNS_Additional[i].Rlen - 1; j++) {
                cout << (int)(MyDNS.DNS_Additional[i].Rdata[j]) << "." ;
            }
            cout << (int)MyDNS.DNS_Additional[i].Rdata[MyDNS.DNS_Additional[i].Rlen -1] << endl;
        } else {
            cout << MyDNS.DNS_Additional[i].Rdata << endl;
        }
    }
}