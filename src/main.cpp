#include "/home/kk/Desktop/socket/DNS_Query/include/dns.h"
#include <cstring>
#include <netinet/in.h>

int main(int argc, const char *argv[]) {
   string ip = "1.1.1.1"; //默认
   //string domain = "www.baidu.com";

   //./main mydig google.com 
   //./main 
   DNS_Message dns(1);
   if (argc < 3 || argc > 4) {
      cout << "命令行参数个数错误， 请重试!" << endl;
      return 0;
   }
   if (argc == 3) {
      dns.GetIP(argv[2], ip);
   }
   dns.PrintTheAnswer();
   return 0;
}