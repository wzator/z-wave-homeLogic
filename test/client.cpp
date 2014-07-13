#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "base64.h"
#include <ifaddrs.h>

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

char *tozero(char *string)
{
    char mem[1024];
    sprintf(mem,"%s",string);
    int counter = 0;
    for (int a=0; a<strlen(mem); a++)
    {
	if ((unsigned char)mem[a] == 0xff)
	{
	    string[counter] = 0;
	}
	else
	{
	    string[counter] = mem[a];
	}

	counter++;
    }
    string[counter+1]=0;
    
    return string;
}

int my_strlen(char *string,int size)
{
    int length;
    int nulss = 0;
    for (length = 0; length < size; string++)
    {
    printf("%x,",(unsigned char)*string);
	if (*string == 0)
	    nulss++;
	else
	    nulss = 0;

	if (nulss > 1)
	{
	    length--;
	    break;
	}

	length++;
    }
printf("\n");
    return(length);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct ifaddrs *ifaddr, *ifa;
    struct hostent *server;
    char buffer[1024];
    char host[NI_MAXHOST];
    char message[1024];
    char part[2048];
    int family;
    portno = 55000;
    server = gethostbyname("192.168.0.140");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
        error("ERROR opening socket");

    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    if (getifaddrs(&ifaddr) == -1) {
	perror("getifaddrs");
	exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
       if (ifa->ifa_addr == NULL)
          continue;

	family = ifa->ifa_addr->sa_family;
	if (family == AF_INET || family == AF_INET6)
	{
	    int s = getnameinfo(ifa->ifa_addr,
		(family == AF_INET) ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6),
	        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	    if (s == 0 && strcmp(ifa->ifa_name,"eth0")==0) {
		    printf("add: %s = %s\n",host,ifa->ifa_name);
		    break;
	    }
	}

    }

    freeifaddrs(ifaddr);

    const std::string mymac		= "01-23-45-67-89-ab";
    const char *appstring		= "iphone..iapp.samsung\0"; 
    const char *tvappstring		= "iphone.LE37C650.iapp.samsung\0"; 
    const std::string myip		= "192.168.0.190";
    const std::string remotename	= "Perl Samsung Remote";
    const std::string skey		= "KEY_3" ; //= "KEY_POWEROFF" ;

    char messagepart1[1024];
    char messagepart2[1024];
    char messagepart3[1024];
    char part1[1024];
    char part2[1024];
    char part3[1024];

    std::string base64mymac		= base64_encode(reinterpret_cast<const unsigned char*>(mymac.c_str()),mymac.length());
    std::string base64remotename	= base64_encode(reinterpret_cast<const unsigned char*>(remotename.c_str()),remotename.length());
    std::string base64skey		= base64_encode(reinterpret_cast<const unsigned char*>(skey.c_str()),skey.length());
    std::string base64myip		= base64_encode(reinterpret_cast<const unsigned char*>(myip.c_str()),myip.length());


printf("encoded:%s\n",base64remotename.c_str());


printf("size: %d\n",strlen(appstring));
    sprintf(messagepart1,"\x64\xFF%c\xFF%s%c\xFF%s%c\xFF%s",strlen(base64myip.c_str()),base64myip.c_str(),strlen(base64mymac.c_str()),base64mymac.c_str(), strlen(base64remotename.c_str()),base64remotename.c_str() );
    sprintf(part1,"\xFF%c\xFF%s%c\xFF%s\0\0",strlen(appstring),appstring,strlen(messagepart1),messagepart1);

    sprintf(messagepart2, "\xc8\xFF");

    sprintf(part2,"\xFF%c\xFF%s%c\xFF%s\0\0",strlen(appstring),appstring,strlen(messagepart2),messagepart2);

    sprintf(messagepart3, "\xFF\xFF\xFF%c\xFF%s",base64skey.length(),base64skey.c_str());

    sprintf(part3,"\xFF%c\xFF%s%c\xFF%s\0\0", strlen(tvappstring), tvappstring, strlen(messagepart3), messagepart3 );


    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

printf("PART1:%s,%d",part1,strlen(part1));
printf("\n");

    int part1l = strlen(part1);
    memcpy(tozero(part1),part1,1000);
    n = write(sockfd,part1,part1l);

printf("PART:%s,%d",part2,strlen(part2));
printf("\n");

    int part2l = strlen(part2);
    memcpy(tozero(part2),part2,1000);
    n = write(sockfd, part2,part2l);

printf("PART:%s,%d",part3,strlen(part3));
printf("\n");

    int part3l = strlen(part3);
    memcpy(tozero(part3),part3,1000);
    n = write(sockfd,part3,part3l);

    if (n < 0) 
         error("ERROR writing to socket");

    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",buffer);
    close(sockfd);
    return 0;
}
