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
      dns.GetIP(argv[2], ip, 1); //默认查询A记录
   }
   //./main mydig -x google.com
   if (argc == 4) {
      if (strcmp("+trace", argv[2]) == 0) {
         
      } else if (strcmp("-x", argv[2]) == 0) {
         dns.GetIP(string(argv[3]) + ".in-addr.arpa", ip, 12);
      } else {
         char name[10];
         int i = 1;
         while (argv[2][i] != '\0') {
            name[i -1] = argv[2][i];
            i ++;
         }
         name[i -1] = '\0';
         dns.GetIP(argv[3], name, 1); //./main mydig @1.1.1.1 google.com
      }
   }
   dns.PrintTheAnswer();
   return 0;
}