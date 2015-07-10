//-----------------------------------------------------------------------------
//
//	Main.cpp v0.20150530
//
//	Based on minimal application to test OpenZWave.
//
//
//	Copyright (c) 2013-2015 Wojciech Zatorski <wojciech@zatorski.net>
//
//
//	OpenZWave SOFTWARE NOTICE AND LICENSE
//
//	This file is part of OpenZWave.
//
//	OpenZWave is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Lesser General Public License as published
//	by the Free Software Foundation, either version 3 of the License,
//	or (at your option) any later version.
//
//	OpenZWave is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Lesser General Public License for more details.
//
//	You should have received a copy of the GNU Lesser General Public License
//	along with OpenZWave.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include "Options.h"
#include "Manager.h"
#include "Driver.h"
#include "Node.h"
#include "Group.h"
#include "Notification.h"
#include "ValueStore.h"
#include "Value.h"
#include "ValueBool.h"
#include "Log.h"
#include <mysql.h>

#include "ServerSocket.h"
#include "SocketException.h"
#include <string>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include <sstream>
#include <errno.h>
#include <time.h>
#include "libgadu.h"
#include "gammu.h"
#include <signal.h>

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <resolv.h>
#include <libssh/libssh.h>
#include "base64.h"
#include <ifaddrs.h>
#include <locale.h>
#include <libintl.h>
#include <curl/curl.h>

#define PACKETSIZE  64
#define _(String) gettext (String)

using namespace OpenZWave;

static uint32 g_homeId = 0;
static bool g_initFailed = false;

int alarmstatus = 0;


struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

typedef struct {
    uint32 m_homeId;
    uint8 m_nodeId;
    bool m_polled;
    list<ValueID> m_values;
} NodeInfo;

struct config_type
{
	char   mysql_host[50];             //Either localhost, IP address or hostname
	char   mysql_user[25];
	char   mysql_passwd[25];
	char   mysql_database[30];
	char   gg_uid[30];
	char   gg_passwd[60];
	char   gg_a1[60];
	char   gg_a2[60];
	int    mysql_port;                 //0 works for local connection
	int    log_level;
	char   sms_phone1[32];
	char   sms_phone2[32];
	char   sms_device[64];
	char   sms_connection[64];
	char   zwave_device[64];
	long int zwave_id;
	int    alarm_node;
	int    light_node;
	int    power_node[255];
	int    valve_node[255];
	int    door_node;
	char   tv_ip[64];
	char   tv_smart[64];
	char   tv_login[50];
	char   tv_pass[50];
	char   tv_start[256];
	char   tv_off[256];
	char   prefix[256];
	int    tv_port;
	int    dynamic[256];
	int    washer_node;
	int    dishwasher_node;
	int    sms_commands;
	int    sms_location;
};


// WASHER variables
float  washer_status		= 0;
int    washer_offcounter	= 0;
struct tm washer_timestart;

float  dishwasher_status	= 0;
int    dishwasher_offcounter	= 0;
struct tm dishwasher_timestart;

// globals
int lastNodeWakeUps		= 0;
long lastNodeWakeUpsHome	= 0;

// Value-Defintions of the different String values

static list<NodeInfo*> g_nodes;
static pthread_mutex_t g_criticalSection;
static pthread_mutex_t g_criticalSectionSMS;
static pthread_cond_t initCond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t initMutex = PTHREAD_MUTEX_INITIALIZER;

// GSM

volatile GSM_Error sms_send_status;
volatile gboolean gshutdown = FALSE;
GSM_StateMachine *stateMachine;
GSM_Config *cfg;

// timer
timer_t firstTimerID;

// config

struct config_type config;

// mysql

MYSQL mysql;

std::map<string, int> MapCommandClassBasic;

int pid = -1;
struct protoent *proto=NULL;
int cnt = 1;


//-----------------------------------------------------------------------------
// <GetNodeInfo>
// Callback that is triggered when a value, group or node changes
//-----------------------------------------------------------------------------

NodeInfo* GetNodeInfo ( uint32 const homeId, uint8 const nodeId)
{
	for ( list<NodeInfo*>::iterator it = g_nodes.begin(); it != g_nodes.end(); ++it )
	{
		NodeInfo* nodeInfo = *it;
		if ( ( nodeInfo->m_homeId == homeId ) && ( nodeInfo->m_nodeId == nodeId ) )
		{
			return nodeInfo;
		}
	}

	return NULL;
}


NodeInfo* GetNodeInfo(Notification const* _notification) {
    uint32 const homeId = _notification->GetHomeId();
    uint8 const nodeId = _notification->GetNodeId();
    for (list<NodeInfo*>::iterator it = g_nodes.begin(); it != g_nodes.end(); ++it) {
        NodeInfo* nodeInfo = *it;
        if ((nodeInfo->m_homeId == homeId) && (nodeInfo->m_nodeId == nodeId)) {
            return nodeInfo;
        }
    }

    return NULL;
}

/* PING ************************************************************************/

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{
    unsigned short *buf =  (unsigned short *)b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


/*--------------------------------------------------------------------*/
/*--- ping - Create message and send it.                           ---*/
/*    return 0 is ping Ok, return 1 is ping not OK.                ---*/
/*--------------------------------------------------------------------*/
int ping(char *adress)
{
    const int val=255;
    int i, sd;
    struct packet pckt;
    struct sockaddr_in r_addr;
    int loop;
    struct hostent *hname;
    struct sockaddr_in addr_ping,*addr;

    pid = getpid();
    proto = getprotobyname("ICMP");
    hname = gethostbyname(adress);
    bzero(&addr_ping, sizeof(addr_ping));
    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

    addr = &addr_ping;

    if (proto == NULL)
    {
	perror(_("getprotobyname errror"));
	return 1;
    }

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if ( sd < 0 )
    {
        perror("socket");
        return 1;
    }
    if ( setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
    {
        perror(_("Set TTL option"));
        close(sd);
        return 1;
    }
    if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 )
    {
        perror(_("Request nonblocking I/O"));
        close(sd);
        return 1;
    }

    for (loop=0;loop < 2; loop++)
    {

        int len=sizeof(r_addr);

        if ( recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, (socklen_t*)&len) > 0 )
        {
	    close(sd);
            return 0;
        }

        bzero(&pckt, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = pid;
        for (i = 0; i < (int) sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = cnt++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        if ( sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
            perror(_("sendto"));

        usleep(300000);

    }

    close(sd);
    return 1;
}


/* SMS *************************************************************************/

//-----------------------------------------------------------------------------
// <snd_sms_callback>
// Send message callback
//-----------------------------------------------------------------------------


void send_sms_callback (GSM_StateMachine *sm, int status, int MessageReference, void * user_data)
{
	printf(_("Sent SMS on device: \"%s\"\n"), GSM_GetConfig(sm, -1)->Device);
	if (status==0) {
		printf(_("..OK"));
		sms_send_status = ERR_NONE;
	} else {
		printf(_("..error %i"), status);
		sms_send_status = ERR_UNKNOWN;
	}
	printf(_(", message reference=%d\n"), MessageReference);
}

/* Function to handle errors */
int error_handler_back(GSM_Error error, GSM_StateMachine *s)
{
	if (error != ERR_NONE) {
		printf(_("ERROR: %s\n"), GSM_ErrorString(error));
		if (GSM_IsConnected(s))
			GSM_TerminateConnection(s);
		return false;
	}

    return true;
}

/* Function to handle errors */
void error_handler(GSM_Error error, GSM_StateMachine *s)
{
	if (error != ERR_NONE) {
		printf(_("ERROR: %s\n"), GSM_ErrorString(error));
		if (GSM_IsConnected(s))
			GSM_TerminateConnection(s);
		pthread_mutex_unlock(&g_criticalSectionSMS);
		exit(error);
	}
}

/* Interrupt signal handler */
void interrupt(int sign)
{
	signal(sign, SIG_IGN);
	gshutdown = TRUE;
}

void toDOT(char txt[])
{
    int w = strlen(txt);
    for (int a=0; a < w; a++)
    {
	if (txt[a] == ',')
	    txt[a]='.';
    }
}


int SMSsendNow(GSM_StateMachine *s, GSM_SMSMessage *smsO, char *message_text)
{
	int return_value = 0;
	GSM_Error error;

    for (int i=0; i<2; i++) 
    {

	if (i==0 && strlen(config.sms_phone1))
	    EncodeUnicode(smsO->Number, config.sms_phone1, strlen(config.sms_phone1));

	if (i==1 && strlen(config.sms_phone2))
	    EncodeUnicode(smsO->Number, config.sms_phone2, strlen(config.sms_phone2));

	EncodeUnicode(smsO->Text, message_text, strlen(message_text));

        sms_send_status = ERR_TIMEOUT;
	error = GSM_SendSMS(s, smsO);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	while (!gshutdown) {
    	    GSM_ReadDevice(s, TRUE);
	    if (sms_send_status == ERR_NONE) {
		/* Message sent OK */
		return_value = 0;
		break;
	    }

	    if (sms_send_status != ERR_TIMEOUT) {
		    	/* Message sending failed */
		    return_value = 100;
		    break;
	    }
	}
    }
    return return_value;

}

int RPC_LoadSMS(GSM_StateMachine *s)
{

	printf("MUTEX_LOCK: LoadSMS\n");
	if (pthread_mutex_trylock(&g_criticalSectionSMS) != 0) {
	    printf("MUTEX_LOCK_BUSY: LoadSMS\n");
	    return 0;
	}

	//pthread_mutex_lock(&g_criticalSectionSMS);
	printf("MUTEX_LOCK_OK: LoadSMS\n");

	usleep(5900000);

	// GSM
	GSM_MultiSMSMessage 	sms;
	GSM_SMSMessage 	smsD;
	GSM_SMSMessage smsO;
	GSM_Error error;
        GSM_SMSFolders folders;
	GSM_SMSC PhoneSMSC;

	/* Register signal handler */
	signal(SIGINT, interrupt);
	signal(SIGTERM, interrupt);

	/*
	 * We don't need gettext, but need to set locales so that
	 * charset conversion works.
	 */
	GSM_InitLocales(NULL);

	/* Connect to phone */
	/* 1 means number of replies you want to wait for */
	error = GSM_InitConnection(s, 1);
	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	GSM_SetSendSMSStatusCallback(s, send_sms_callback, NULL);

	error = GSM_GetSMSFolders(s, &folders);
	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	memset(&sms, 0, sizeof(sms));
	memset(&smsD, 0, sizeof(smsD));

	/* We need to know SMSC number */
	PhoneSMSC.Location = 1;
	error = GSM_GetSMSC(s, &PhoneSMSC);
	if (error_handler_back(error,s) == false) {
    	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	/* Read all messages */
	error = ERR_NONE;

	memset(&smsO, 0, sizeof(smsO));
	smsO.PDU = SMS_Submit;
	smsO.UDH.Type = UDH_NoUDH;
	smsO.Coding = SMS_Coding_Default_No_Compression;
	smsO.Class = 1;

	/* Set SMSC number in message */
	CopyUnicodeString(smsO.SMSC.Number, PhoneSMSC.Number);

	for (int a=0; a<10; a++)
	{
	    sms.Number = 0;
	    sms.SMS[0].Location = a + config.sms_location;
	    sms.SMS[0].Folder = 0;

	    error=GSM_GetSMS(s, &sms);

	    if (sms.Number != 0)
	    {
		printf(_("Number: %d\n"),sms.Number);
	        printf(_("Location: %d, Folder: %d\n"), sms.SMS[0].Location, sms.SMS[0].Folder);
	        printf(_("Number: \"%s\"\n"), DecodeUnicodeConsole(sms.SMS[0].Number));

		char text[256];
		char mynumber[256];
		sprintf(mynumber, "%s", DecodeUnicodeConsole(sms.SMS[0].Number));

		if (sms.SMS[0].Coding == SMS_Coding_8bit) {
			printf(_("8-bit message, can not display\n"));
		} else {
			sprintf(text,"%s", DecodeUnicodeConsole(sms.SMS[0].Text));
			printf(_("Text: \"%s\"\n"), DecodeUnicodeConsole(sms.SMS[0].Text));
		}


		if ((strlen(config.sms_phone1) > 0 && strstr(mynumber,config.sms_phone1)!= NULL) || (strstr(mynumber,config.sms_phone2)!= NULL && strlen(config.sms_phone2) > 0))
		{
		    if (strcmp(text,"LOCK")==0)
		    {
			pthread_mutex_lock(&g_criticalSection);
		        char query[256];
			sprintf(query,"UPDATE parameters SET parValue = 1 WHERE parName = 'alarmOn' LIMIT 1");
			mysql_query(&mysql,query);

			int lastid = mysql_insert_id(&mysql);

		        pthread_mutex_unlock(&g_criticalSection);

			if (lastid > 0) 
			{
			    char message_text[256];
			    sprintf(message_text,"[%s] %s",config.prefix, _("LOCK active"));
			    SMSsendNow(s, &smsO, message_text);
			}
		    }

		    if (strcmp(text,"UNLOCK")==0)
		    {
			pthread_mutex_lock(&g_criticalSection);
		        char query[256];
			sprintf(query,"UPDATE parameters SET parValue = 0 WHERE parName = 'alarmOn' LIMIT 1");
			mysql_query(&mysql,query);

			int lastid = mysql_insert_id(&mysql);

		        pthread_mutex_unlock(&g_criticalSection);

			if (lastid > 0) 
			{
			    char message_text[256];
			    sprintf(message_text,"[%s] %s",config.prefix, _("LOCK deactivated"));
			    SMSsendNow(s, &smsO, message_text);
			}
		    }

		    if (strcmp(text,"FREEDAY")==0)
		    {
			pthread_mutex_lock(&g_criticalSection);
		        char query[256];
		        sprintf(query,"INSERT INTO zonesFree (date) VALUES (NOW())");
			mysql_query(&mysql,query);

			int lastid = mysql_insert_id(&mysql);

		        pthread_mutex_unlock(&g_criticalSection);

			if (lastid > 0) 
			{
			    char message_text[256];
			    sprintf(message_text,"[%s] %s",config.prefix, _("FREEDAY active"));
			    SMSsendNow(s, &smsO, message_text);
			}

		    }

		    if (strcmp(text,"ALWAYSON")==0)
		    {
			pthread_mutex_lock(&g_criticalSection);
		        char query[256];
		        sprintf(query,"UPDATE parameters SET parValue = 1 WHERE parName='sensorAlwaysOn'");
			mysql_query(&mysql,query);

		        pthread_mutex_unlock(&g_criticalSection);

			char message_text[256];
			sprintf(message_text,"[%s] %s",config.prefix,_("ENABLED: Sensors always on"));
			SMSsendNow(s, &smsO, message_text);

		    }

		    if (strcmp(text,"ALWAYSOFF")==0)
		    {
			pthread_mutex_lock(&g_criticalSection);
		        char query[256];
		        sprintf(query,"UPDATE parameters SET parValue = 0 WHERE parName='sensorAlwaysOn'");
			mysql_query(&mysql,query);

		        pthread_mutex_unlock(&g_criticalSection);

			char message_text[256];
			sprintf(message_text,"[%s] %s",config.prefix,_("DISABLED: Sensors always on"));
			SMSsendNow(s, &smsO, message_text);


		    }

		}

		smsD.Location = a + config.sms_location;
		smsD.Folder = 0;
		GSM_DeleteSMS(s, &smsD);
	    }
	}


	/* Terminate connection */
	error = GSM_TerminateConnection(s);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}



	pthread_mutex_unlock(&g_criticalSectionSMS);

	return 0;

}

int RPC_SendSMS(char *recipient_number, char *message_text, GSM_StateMachine *s)
{
// GSM
	printf("MUTEX_LOCK: SendSMS\n");
	pthread_mutex_lock(&g_criticalSectionSMS);
	printf("MUTEX_LOCK_OK: SendSMS\n");
	usleep(15900000);
	GSM_Error error;

	GSM_SMSMessage sms;
	GSM_SMSC PhoneSMSC;
	int return_value = 0;

	/* Register signal handler */
	signal(SIGINT, interrupt);
	signal(SIGTERM, interrupt);

	/*
	 * We don't need gettext, but need to set locales so that
	 * charset conversion works.
	 */
	GSM_InitLocales(NULL);


	/* Prepare message */
	/* Cleanup the structure */
	memset(&sms, 0, sizeof(sms));
	/* Encode message text */
	EncodeUnicode(sms.Text, message_text, strlen(message_text));
	/* Encode recipient number */
	EncodeUnicode(sms.Number, recipient_number, strlen(recipient_number));
	/* We want to submit message */
	sms.PDU = SMS_Submit;
	/* No UDH, just a plain message */
	sms.UDH.Type = UDH_NoUDH;
	/* We used default coding for text */
	sms.Coding = SMS_Coding_Default_No_Compression;
	/* Class 1 message (normal) */
	sms.Class = 1;

	/* Connect to phone */
	/* 1 means number of replies you want to wait for */
	error = GSM_InitConnection(s, 3);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	/* Set callback for message sending */
	/* This needs to be done after initiating connection */
	GSM_SetSendSMSStatusCallback(s, send_sms_callback, NULL);

	/* We need to know SMSC number */
	PhoneSMSC.Location = 1;
	error = GSM_GetSMSC(s, &PhoneSMSC);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	/* Set SMSC number in message */
	CopyUnicodeString(sms.SMSC.Number, PhoneSMSC.Number);

	/*
	 * Set flag before callind SendSMS, some phones might give
	 * instant response
	 */
	sms_send_status = ERR_TIMEOUT;

	/* Send message */
	error = GSM_SendSMS(s, &sms);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	/* Wait for network reply */
	while (!gshutdown) {
		GSM_ReadDevice(s, TRUE);
		if (sms_send_status == ERR_NONE) {
			/* Message sent OK */
			return_value = 0;
			break;
		}
		if (sms_send_status != ERR_TIMEOUT) {
			/* Message sending failed */
			return_value = 100;
			break;
		}
	}

	/* Terminate connection */
	error = GSM_TerminateConnection(s);

	if (error_handler_back(error,s) == false) {
	    pthread_mutex_unlock(&g_criticalSectionSMS);
	    return -1;
	}

	pthread_mutex_unlock(&g_criticalSectionSMS);

	return return_value;
}

/* TV SAMSUNG Remote Controll ********************************************************/

char *tozero(char *string)
{
    char mem[1024];
    sprintf(mem,"%s",string);
    int counter = 0;
    for (int a=0; a < (int) strlen(mem); a++)
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

int tvRemote(std::string skey, std::string myip, std::string remoteip)
{
    int 	sockfd, portno, n;
    struct	sockaddr_in serv_addr;
    struct	ifaddrs *ifaddr, *ifa;
    struct	hostent *server;
    char	buffer[1024];
    char	host[NI_MAXHOST];
    int		family;

    portno = 55000;
    server = gethostbyname(remoteip.c_str());
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror(_("ERROR opening socket"));
        return -1;
    }

    if (server == NULL) {
        fprintf(stderr,_("ERROR, no such host\n"));
        return -1;
    }

    if (getifaddrs(&ifaddr) == -1) {
	perror(_("getifaddrs"));
	return -1;
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
		    printf(_("add: %s = %s\n"),host,ifa->ifa_name);
		    break;
	    }
	}

    }

    freeifaddrs(ifaddr);

    const std::string mymac		= "01-23-45-67-89-ab";
    const char *appstring		= "iphone..iapp.samsung\0"; 
    const char *tvappstring		= "iphone.LE37C650.iapp.samsung\0"; 
    const std::string remotename	= "Perl Samsung Remote";

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
    {
        perror(_("ERROR connecting"));
        return -1;
    }


    int part1l = strlen(part1);
    memcpy(tozero(part1),part1,1000);
    n = write(sockfd,part1,part1l);

    int part2l = strlen(part2);
    memcpy(tozero(part2),part2,1000);
    n = write(sockfd, part2,part2l);

    int part3l = strlen(part3);
    memcpy(tozero(part3),part3,1000);
    n = write(sockfd,part3,part3l);

    if (n < 0) 
    {
         perror(_("ERROR writing to socket"));
    }

    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) 
         perror(_("ERROR reading from socket"));

    close(sockfd);
    return 0;
}

/* SSH ******************************************************************************/

/* execute remote command */

int show_remote_processes(ssh_session session, const char *command)
{
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;
    channel = channel_new(session);

    if (channel == NULL)
	return SSH_ERROR;
	rc = channel_open_session(channel);

    if (rc != SSH_OK)
    {
	channel_free(channel);
	return rc;
    }

    rc = channel_request_exec(channel, command);
    if (rc != SSH_OK)
    {
	channel_close(channel);
	channel_free(channel);
        return rc;
    }

    nbytes = channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        if (write(1, buffer, nbytes) != (int) nbytes)
	{
            channel_close(channel);
    	    channel_free(channel);
    	    return SSH_ERROR;
        }
	nbytes = channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0)
    {
	channel_close(channel);
	channel_free(channel);
	return SSH_ERROR;
    }

    channel_send_eof(channel);
    channel_close(channel);
    channel_free(channel);
    return SSH_OK;
}


/* Validate remote host */

int verify_knownhost(ssh_session session)
{
    int state, hlen;
    unsigned char *hash = NULL;
    char *hexa;

    state = ssh_is_server_known(session);
    hlen = ssh_get_pubkey_hash(session, &hash);

    if (hlen < 0)
        return -1;
    switch (state)
    {
    case SSH_SERVER_KNOWN_OK:
	break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr, _("Host key for server changed: it is now:\n"));
        ssh_print_hexa(_("Public key hash"), hash, hlen);
        fprintf(stderr, _("For security reasons, connection will be stopped\n"));
	free(hash);
	return -1;
    case SSH_SERVER_FOUND_OTHER:
	fprintf(stderr, _("The host key for this server was not found but an other type of key exists.\n"));
	fprintf(stderr, _("An attacker might change the default server key to confuse your client into thinking the key does not exist\n"));
	free(hash);
	return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
	fprintf(stderr, _("Could not find known host file.\n"));
	fprintf(stderr, _("If you accept the host key here, the file will be automatically created.\n"));
	/* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
	hexa = ssh_get_hexa(hash, hlen);
	fprintf(stderr,_("The server is unknown. Do you trust the host key?\n"));
	fprintf(stderr, _("Public key hash: %s\n"), hexa);
	free(hexa);

    if (ssh_write_knownhost(session) < 0)
    {
	fprintf(stderr, _("Error %s\n"), strerror(errno));
        free(hash);
	return -1;
    }

    break;
    case SSH_SERVER_ERROR:
	fprintf(stderr, _("Error %s"), ssh_get_error(session));
	    free(hash);
	    return -1;
	}
	free(hash);
	return 0;
}


/* Make connection, execute command */

int RPC_SSHdo(const char *command, const char *cfg_host, const char *cfg_login, const char *cfg_password)
{
    ssh_session my_ssh_session;
    int rc;

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
	return (-1);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, cfg_host);
    // Connect to server
    rc = ssh_connect(my_ssh_session);

    if (rc != SSH_OK)
    {
        fprintf(stderr, _("Error connecting to localhost: %s\n"),
        ssh_get_error(my_ssh_session));
	ssh_free(my_ssh_session);
        return (-1);
    }

    // Verify the server's identity
    // For the source code of verify_knowhost(), check previous example
    if (verify_knownhost(my_ssh_session) < 0)
    {
	ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
	return(-1);
    }

    // Authenticate ourselves
    rc = ssh_userauth_password(my_ssh_session, cfg_login, cfg_password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, _("Error authenticating with password: %s\n"),
        ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
	return(-1);
    }

    show_remote_processes(my_ssh_session, command);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}


/* GaduGadu *************************************************************************/

//-----------------------------------------------------------------------------
// <RPC_SendGG>
// Send message to gg client
//-----------------------------------------------------------------------------

int RPC_SendGG(int number, unsigned char *text)
{
	struct gg_session *sess;
	struct gg_event *e;
	struct gg_login_params p;

	memset(&p, 0, sizeof(p));
	p.uin = atoi(config.gg_uid);
	p.password = config.gg_passwd;
	
	if (!(sess = gg_login(&p))) {
		printf(_("Can not connect: %s\n"), strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	if (gg_notify(sess, NULL, 0) == -1) {	/* serwery gg nie pozwalaja wysylac wiadomosci bez powiadomienia o userliscie (przetestowane p.protocol_version [0x15; def] */
		printf(_("Connection aborted: %s\n"), strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	if (gg_send_message(sess, GG_CLASS_MSG, number, (unsigned char*) text) == -1) {
		printf(_("Connection aborted: %s\n"), strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	/* poniższą część można olać, ale poczekajmy na potwierdzenie */

	while (0) {
		if (!(e = gg_watch_fd(sess))) {
			printf(_("Connection broken: %s\n"), strerror(errno));
			gg_logoff(sess);
			gg_free_session(sess);
			return 1;
		}

		if (e->type == GG_EVENT_ACK) {
			printf(_("Send.\n"));
			gg_free_event(e);
			break;
		}

		gg_free_event(e);
	}

	gg_logoff(sess);
	gg_free_session(sess);

    return 0;

}

bool setPoint (int32 home, int32 node, string int_value)
{
	bool response = 0;

	if ( NodeInfo* nodeInfo = GetNodeInfo( home, node ) )
	{
		// Find the correct instance
		for ( list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it )
		{
			int id = (*it).GetCommandClassId();
			//int inst = (*it).GetInstance();
			int index = (*it).GetIndex();
			if (id == 67 && index == 1)
			{
				response = Manager::Get()->SetValue( *it, int_value );

			    printf(_("Command class: %d\n"),id);
			}
		}
	}

    return response;

}

bool setValueByAll ( int32 home, int32 node, int32 myid, int32 instance, int32 myindex, const void *myvalue )
{
	bool response = 0;
	bool bool_value;
	int32 value = *(int*) myvalue;

	if ( NodeInfo* nodeInfo = GetNodeInfo( home, node ) )
	{
		for ( list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it )
		{
			int id = (*it).GetCommandClassId();
			int inst = (*it).GetInstance();
			int index = (*it).GetIndex();


			printf("%d,%d,%d = %d\n",id,inst,index,(*it).GetType());
			if ( id == myid && instance == inst && index == myindex )
			{
				if ( ValueID::ValueType_Bool == (*it).GetType() )
				{
				    bool_value = (bool)value;
				    response = Manager::Get()->SetValue( *it, bool_value );
				}
				else if ( ValueID::ValueType_Button == (*it).GetType() )
				{
				    if (value == 0)
    			    		response = Manager::Get()->PressButton( *it ); 
    			    	    else
    			    		response = Manager::Get()->ReleaseButton( *it );
				}
				else if ( ValueID::ValueType_Byte == (*it).GetType() )
				{
				    uint8 uint8_value = (uint8)value;
				    response = Manager::Get()->SetValue( *it, uint8_value );
				}
				else if ( ValueID::ValueType_Decimal == (*it).GetType() )
				{
				    string tmp;
				    sprintf((char*)tmp.c_str(), "%d", value);
				    string decimal = tmp.c_str();
				    response = Manager::Get()->SetValue( *it, decimal );
				}
				else if ( ValueID::ValueType_Short == (*it).GetType() )
				{
				    uint16 uint16_value = (uint16)value;
				    response = Manager::Get()->SetValue( *it, uint16_value );
				}
				else if ( ValueID::ValueType_Int == (*it).GetType() )
				{
				    int int_value = value;
				    response = Manager::Get()->SetValue( *it, int_value );
				}
				else if ( ValueID::ValueType_List == (*it).GetType() )
				{
				    const char* mvalue = (char*)myvalue;
				    std::string mvalue1 = std::string(mvalue);
				    response = Manager::Get()->SetValueListSelection( *it , mvalue1);
				}
				
				printf("SetvalueByAll(%d:%d:%d) type: %d value %d \n", response, inst,id, (*it).GetType(), value);
			}
		}

	}

    return response;

}


bool setValueByInstance (int32 home, int32 node, const void *myvalue, int32 instance)
{
	bool response = 0;
	bool bool_value;
	int value = *(int*) myvalue;

	if ( NodeInfo* nodeInfo = GetNodeInfo( home, node ) )
	{
		for ( list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it )
		{
			int id = (*it).GetCommandClassId();
			int inst = (*it).GetInstance();
			if ( (id == 0x25 || id == 0x28 || id == 0x20) && instance == inst )
			{
				if ( ValueID::ValueType_Bool == (*it).GetType() )
				{
				    bool_value = (bool)value;
				    response = Manager::Get()->SetValue( *it, bool_value );
				}
				else if ( ValueID::ValueType_Byte == (*it).GetType() )
				{
				    uint8 uint8_value = (uint8)value;
				    response = Manager::Get()->SetValue( *it, uint8_value );
				}
				else if ( ValueID::ValueType_Decimal == (*it).GetType() )
				{
				    string tmp;
				    sprintf((char*)tmp.c_str(), "%d", value);
				    string decimal = tmp.c_str();
				    response = Manager::Get()->SetValue( *it, decimal );
				}
				else if ( ValueID::ValueType_Short == (*it).GetType() )
				{
				    uint16 uint16_value = (uint16)value;
				    response = Manager::Get()->SetValue( *it, uint16_value );
				}
				else if ( ValueID::ValueType_Int == (*it).GetType() )
				{
				    int int_value = value;
				    response = Manager::Get()->SetValue( *it, int_value );
				}
				else if ( ValueID::ValueType_List == (*it).GetType() )
				{
				    const char* mvalue = (char*)myvalue;
				    std::string mvalue1 = std::string(mvalue);
				    response = Manager::Get()->SetValueListSelection( *it , mvalue1);
				}
				
				printf("SetvalueByInstance(%d:%d:%d) type: %d \n", response, inst,id, (*it).GetType());
			}
		}

	}

    return response;

}

bool setValue (int32 home, int32 node, int32 value)
{
	bool response = 0;
	bool bool_value;

	if ( NodeInfo* nodeInfo = GetNodeInfo( home, node ) )
	{
		for ( list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it )
		{
			int id = (*it).GetCommandClassId();
			int inst = (*it).GetInstance();
			if ( id == 0x25 || id == 0x28 || id == 0x20 )
			{
				if ( ValueID::ValueType_Bool == (*it).GetType() )
				{
				    bool_value = (bool)value;
				    response = Manager::Get()->SetValue( *it, bool_value );
				}
				else if ( ValueID::ValueType_Byte == (*it).GetType() )
				{
				    uint8 uint8_value = (uint8)value;
				    response = Manager::Get()->SetValue( *it, uint8_value );
				}
				else if ( ValueID::ValueType_Decimal == (*it).GetType() )
				{
				    string tmp;
				    sprintf((char*)tmp.c_str(), "%d", value);
				    string decimal = tmp.c_str();
				    response = Manager::Get()->SetValue( *it, decimal );
				}
				else if ( ValueID::ValueType_Short == (*it).GetType() )
				{
				    uint16 uint16_value = (uint16)value;
				    response = Manager::Get()->SetValue( *it, uint16_value );
				}
				else if ( ValueID::ValueType_Int == (*it).GetType() )
				{
				    int int_value = value;
				    response = Manager::Get()->SetValue( *it, int_value );
				}
				else if ( ValueID::ValueType_List == (*it).GetType() )
				{
				    response = Manager::Get()->SetValue( *it, value );
				}
				
				printf("Setvalue(%d:%d:%d) type: %d \n", response, inst,id, (*it).GetType());
			}
		}

	}

    return response;
}


/* TV MANAGER ************************************* */

// on/off TV

int tvManager(char *option, char *mkeys)
{

    signal(SIGCHLD, SIG_IGN); // don't wait for children
    int forked = fork();

    if (forked == 0)
    {
	char keys[1024];
	
	sprintf(keys,"%s",mkeys);

	// only tv on
	if (strcmp(option,"TVON")==0)
	{
	    RPC_SSHdo(config.tv_start, config.tv_smart, config.tv_login, config.tv_pass);
	}

	// only tv off
	if (strcmp(option,"TVOFF")==0)
	{
	    RPC_SSHdo(config.tv_off, config.tv_smart, config.tv_login, config.tv_pass);
	}

	// set channel to TV
	if (strcmp(option,"TVKEYTV")==0)
	{
	    std::string skey = "KEY_TV";
	    tvRemote(skey, "192.168.0.1", config.tv_ip);
	}

	if (strcmp(option,"POWERON")==0)
	{
	    RPC_SSHdo(config.tv_start, config.tv_smart, config.tv_login, config.tv_pass);

		if (strlen(keys)>2)
	        {
    		    usleep(15900000);/* WAIT FOR TV TO RUN */

		    char *p = strtok(keys,";");
		    while (p != NULL)
		    {
			std::string skey = p;
			printf("SKEY: %s\n",p);

			usleep(6500000); /* CEC sloooow */
			tvRemote(skey, "192.168.0.1", config.tv_ip);
		        p = strtok(NULL, ";");
		    }

		}
	}

	if (strcmp(option,"POWEROFF")==0)
	{
	    RPC_SSHdo(config.tv_off, config.tv_smart, config.tv_login, config.tv_pass);

		if (strlen(keys)>2)
	        {
		    sleep(15); /* CEC sloooow */
		    char *p = strtok(keys,";");
		    while (p != NULL)
		    {
			std::string skey = p;

			tvRemote(skey, "192.168.0.1", config.tv_ip);
			p = strtok(NULL, ";");
		    }
		}
	}

	_exit(3);
    }

    return 0;

}


/* ALARMS ***************************************** */

//-----------------------------------------------------------------------------
// <alarm>
// 
//-----------------------------------------------------------------------------


void *smsNow(void * minfo)
{
	char info[1024];

	sprintf(info,"%s",minfo);
	int res = 0;

	if (strlen(config.sms_phone1) > 0)
    	    res = RPC_SendSMS(config.sms_phone1, (char *) info, stateMachine);

	// if error try again
    	if (res == -1) {
	    usleep(900000);
    	    res = RPC_SendSMS(config.sms_phone1, (char *) info, stateMachine);
	}
	
	if (strlen(config.sms_phone2) > 0)
	    res = RPC_SendSMS(config.sms_phone2, (char *) info, stateMachine);

	// if error try again
    	if (res == -1) {
	    usleep(900000);
    	    res = RPC_SendSMS(config.sms_phone2, (char *) info, stateMachine);
	}

	pthread_exit(NULL);
}

void alarm(char *info)
{
		if (strlen(config.gg_a1) > 0)
			RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

		if (strlen(config.gg_a2) > 0)
			RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);

		if (strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
		{
		    pthread_t sms_thread; 
		    pthread_create(&sms_thread, NULL, smsNow, info);
		    usleep(900000);
		}

}


//-----------------------------------------------------------------------------
// <zones_validate>
// 
//-----------------------------------------------------------------------------

void zones_validate(int nodeId, long int homeId)
{
    char query[4096];
    char info[1024];

    MYSQL_RES *result;
    MYSQL_ROW row;

    sprintf(query,"SELECT parValue FROM parameters WHERE parName = 'sensorAlwaysOn' LIMIT 1");
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);
    row = mysql_fetch_row(result);
    mysql_free_result(result);

    if (atoi(row[0]) > 0)
    {
	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);

	sprintf(query,"SELECT ignoreNode FROM nodes WHERE id = %d AND homeid = %d LIMIT 1", nodeId, homeId);
	mysql_query(&mysql,query);
	result = mysql_store_result(&mysql);
        row = mysql_fetch_row(result);
	mysql_free_result(result);

	if (atoi(row[0]) == 0)
	{
	    sprintf(info,_("[%s] - MOVE AUTO - : Node %d Home %d Date %s"), config.prefix, nodeId, homeId, asctime(timeinfo));
	    printf(info);
	    alarm(info);
	    return ;
	}
	else
	{
	    sprintf(info,_("- IGNORE AUTO - : Node %d Home %d Date %s"), nodeId, homeId, asctime(timeinfo));
	    printf(info);
	}
    }

    sprintf(query,"SELECT COUNT(*) AS cdx FROM zonesFree WHERE zonesFree.date = DATE(NOW())");
    mysql_query(&mysql,query);
    result	= mysql_store_result(&mysql);
    row		= mysql_fetch_row(result);
    int skipZones = atoi(row[0]);
    mysql_free_result(result);

    sprintf(query,"SELECT COUNT(*) AS cdx FROM zones WHERE homeid = %d AND node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) )  AND active = 1", homeId, nodeId);
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);

    row = mysql_fetch_row(result);

    if (atoi(row[0]) > 0 && skipZones < 1)
    {
		time_t rawtime;
		struct tm * timeinfo;
		
		time(&rawtime);
		timeinfo = localtime(&rawtime);
    
		sprintf(info,_("[%s] - MOVE - : Node %d Date %s"), config.prefix, nodeId, asctime(timeinfo));
		printf(info);
		alarm(info);
	
    }
    else
    {
	printf(_("No move [%d]\n"), row[0]);
    }

    mysql_free_result(result);

    sprintf(query,"SELECT id FROM zonesAction WHERE homeid = %d AND node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) )  AND DATE(zonesAction.timestamp) != DATE(NOW())",homeId,nodeId);
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);

    while ((row = mysql_fetch_row(result)))
    {
	sprintf(query,"UPDATE zonesAction SET zonesAction.timestamp = NOW(), zonesAction.query=zonesAction.query+1 WHERE id = %s LIMIT 1", row[0]);
        mysql_query(&mysql,query);

		time_t rawtime;
		struct tm * timeinfo;
		
		time(&rawtime);
		timeinfo = localtime(&rawtime);
    
		sprintf(info,_("[%s] - ONE MOVE - : Node %d Date %s"), config.prefix, nodeId, asctime(timeinfo));
		printf(info);
		alarm(info);

    }

    mysql_free_result(result);

}


/* Z-Wave *************************************************************************/


//-----------------------------------------------------------------------------
// <RPC_WakeUp>
// Function that is triggered when a value, group or node changes
//-----------------------------------------------------------------------------

void RPC_WakeUp( int homeID, int nodeID, Notification const* _notification )
{
	char query[4096];

        sprintf(query, "INSERT INTO wakeup (homeid,node) VALUES (");
	sprintf(query, "%s%d,%d",query,homeID,nodeID);

	sprintf(query, "%s)",query);

        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, _("Could not insert row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
        }


    lastNodeWakeUpsHome	= homeID;
    lastNodeWakeUps	= nodeID;
}

//-----------------------------------------------------------------------------
// <RPC_NodeProtocolInfo>
// We got results to a Protocol Info query.
//-----------------------------------------------------------------------------

/*
void RPC_NodeProtocolInfo( int homeID, int nodeID, Notification const* _notification )
{
	xmlrpc_int32 basic = Manager::Get()->GetNodeBasic( homeID, nodeID );
	xmlrpc_int32 generic = Manager::Get()->GetNodeGeneric( homeID, nodeID );
	xmlrpc_int32 specific = Manager::Get()->GetNodeSpecific( homeID, nodeID );
	xmlrpc_bool listening = Manager::Get()->IsNodeListeningDevice( homeID, nodeID );
	xmlrpc_bool frequentlistening = Manager::Get()->IsNodeFrequentListeningDevice( homeID, nodeID );
	xmlrpc_bool beaming = Manager::Get()->IsNodeBeamingDevice( homeID, nodeID );
	xmlrpc_bool routing = Manager::Get()->IsNodeRoutingDevice( homeID, nodeID );
	xmlrpc_bool security = Manager::Get()->IsNodeSecurityDevice( homeID, nodeID );
	xmlrpc_int32 maxbaudrate = Manager::Get()->GetNodeMaxBaudRate( homeID, nodeID );
	const char* nodetype = Manager::Get()->GetNodeType( homeID, nodeID).c_str();
	const char* name = Manager::Get()->GetNodeName( homeID, nodeID).c_str();
	const char* location = Manager::Get()->GetNodeLocation( homeID, nodeID).c_str();
	uint8 version = Manager::Get()->GetNodeVersion( homeID, nodeID ); 
	uint8 basicmapping = 0;
	char buffer[50];

	// Get NodeInfo information
	if ( NodeInfo* nodeInfo = GetNodeInfo( _notification ) )
	{
		// This is a "new" node, we set basicmapping to 0 now
		nodeInfo->setMapping(0);

		// Convert Generic+Specific to string
		snprintf( buffer,20, "0x%02X|0x%02X", generic, specific );

		// Check if we have a mapping in our map table
		if ( MapCommandClassBasic.find(buffer) != MapCommandClassBasic.end() )
		{
			nodeInfo->basicmapping = MapCommandClassBasic[buffer];
			basicmapping = MapCommandClassBasic[buffer];
		} else {

			// We didn't find a Generic+Specifc in the table, now we check
			// for Generic only
			snprintf( buffer,20, "0x%02X", generic );

			// Check if we have a mapping in our map table
			if ( MapCommandClassBasic.find(buffer) != MapCommandClassBasic.end() )
			{
				nodeInfo->basicmapping = MapCommandClassBasic[buffer];
				basicmapping = MapCommandClassBasic[buffer];
			}
		}
	}
}
*/

//-----------------------------------------------------------------------------
// <RPC_NodeEvent>
//
//-----------------------------------------------------------------------------

void RPC_NodeEvent( int homeID, int nodeID, ValueID valueID, int value )
{
	int instanceID = valueID.GetInstance();
	char dev_value[1024];
	char query[4096];
	char startedQry[32];
	int myNodes[100][4];
	MYSQL_RES *result;
        MYSQL_ROW row;

	// Instance can never be zero, we need to be backwards compatible
	if ( instanceID == 0 ) {
		instanceID = 1;
	}

	printf(_("BASIC_CLASS: HomeId=%d Node=%d Value=%d\n"), homeID, nodeID, value );

	snprintf( dev_value, 1024, "%d", value );

        sprintf(query, "INSERT INTO basic (homeid,node,instance,valueINT,parentId) VALUES (");

	if (value == 0)
	    sprintf(query, "%s%d,%d,%d,\'%s\',(SELECT MAX(id) FROM basic AS b WHERE node = %d AND valueINT > 0 AND homeid = %d)",query,homeID,nodeID,instanceID,dev_value,nodeID, homeID);
	else
	    sprintf(query, "%s%d,%d,%d,\'%s\',NULL",query,homeID,nodeID,instanceID,dev_value);

	sprintf(query, "%s)",query);

/*
	if (nodeID == 5 && value == 255)
	{
	     bool res = setValue(g_homeId,config.light_node,255);
	}

	if (nodeID == 5 && value == 0)
	{
	     bool res = setValue(g_homeId,config.light_node,0);
	}
*/
        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, _("Could not insert row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
        }

/* lights management */

	if ( value > 0) /* sensorNode ON */
	{
	    sprintf(query,"SELECT lightNode,id,dependsOnNode,dependsLastAction FROM zonesLights WHERE homeid = %d AND sensorNode = %d AND TIME(NOW()) >= timeStart AND TIME(NOW()) <= timeEnd AND active = 1 ", homeID, nodeID);
	    sprintf(startedQry,"1");
	}
	else
	{
	    sprintf(query,"SELECT lightNode,id,dependsOnNode,dependsLastAction FROM zonesLights WHERE ((sensorNode = %d AND endNode IS NULL) OR (endNode = %d AND startedQry IS NOT NULL)) AND active = 1 AND TIME(NOW()) >= timeStart AND TIME(NOW()) <= timeEnd AND homeid = %d", nodeID, nodeID, homeID);
	    sprintf(startedQry,"NULL");
	}

        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, _("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
	}
	else
	{
	    result = mysql_store_result(&mysql);
	    int i=0;
    	    char *garbage = NULL;
	    while ((row = mysql_fetch_row(result)))
	    {
		if (row[0])
		    myNodes[i][0]=strtol(row[0],&garbage,0);
		else
		    myNodes[i][0]=0;

		if (row[1])
		    myNodes[i][1]=strtol(row[1],&garbage,0);
		else
		    myNodes[i][1]=0;

		if (row[2])
		    myNodes[i][2]=strtol(row[2],&garbage,0);
		else
		    myNodes[i][2]=0;

		if (row[3])
		    myNodes[i][3]=strtol(row[3],&garbage,0);
		else
		    myNodes[i][3]=0;

		i++;
	    }

	    mysql_free_result(result);

	    for (int a=0; a<i; a++)
	    {
		int skip = 0;
		if (myNodes[a][2] > 1)
		{
		    int lastTime = myNodes[a][3];
		    sprintf(query,"(SELECT ROUND(TIME_TO_SEC(TIMEDIFF(NOW(),basic.timestamp)) / 60) AS nodeTime, valueINT, basic.timestamp  FROM basic WHERE node = %d AND homeid = %d ORDER BY basic.timestamp DESC LIMIT 1) UNION (SELECT ROUND(TIME_TO_SEC(TIMEDIFF(NOW(),switches.timestamp)) / 60) AS nodeTime, status, switches.timestamp  FROM switches WHERE node = %d AND homeid = %d ORDER BY switches.timestamp DESC LIMIT 1)", myNodes[a][2],homeID,myNodes[a][2],homeID);
    		    if(mysql_query(&mysql, query))
    		    {
    		        fprintf(stderr, _("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
		    }
		    else
		    {
			MYSQL_RES *resultL;
		        MYSQL_ROW rowL;
	    	        resultL = mysql_store_result(&mysql);
			int num_rows = mysql_num_rows(resultL);

			if (num_rows > 0)
			{
	        	        rowL = mysql_fetch_row(resultL);

				if (rowL[0])
				{
	    			    if (atoi(rowL[0]) < lastTime)
	    	    		    {
	    	    			skip++;
	    	    		        printf(_("Skip Node %d from %d (time %s/%s last time %d : %s)\n"),myNodes[a][0],myNodes[a][2],rowL[0],rowL[1],lastTime,rowL[2]);
	    	    		    }
	    	    		}
	    	    	}

			mysql_free_result(resultL);
	    	    }

		}

		if (skip == 0)
		{
		    sprintf(query,"UPDATE zonesLights SET startedQry = %s WHERE id = %d LIMIT 1",startedQry,myNodes[a][1]);
		    mysql_query(&mysql,query);
		    setValue(g_homeId,myNodes[a][0],atoi(dev_value));
		    printf("zonesLights SET %d = %d\n",myNodes[a][0],atoi(dev_value));
		}
	    }

	}

/* **************** */

	/* for alarms when 255 is returned */
	if (value == 255)
	{
	    zones_validate(nodeID,homeID);
	    printf(_("Zones validate for node %d"),nodeID);
	}

}



//-----------------------------------------------------------------------------
// <RPC_ValueChanhed>
// Function that is triggered when a value, group or node changes
//-----------------------------------------------------------------------------

void RPC_ValueChanged( int homeID, int nodeID, ValueID valueID, bool add, Notification const* _notification )
{
	int id		= valueID.GetCommandClassId();
	int genre	= valueID.GetGenre();
	string label	= Manager::Get()->GetValueLabel( valueID );
	int instanceID	= valueID.GetInstance();
	int type	= valueID.GetType();
	char dev_value[1024];
	uint8 byte_value;
	bool bool_value;
	string decimal_value;
	string list_value;
	string string_value;
	int int_value;
	int16 short_value;
	string str_tmp;
	NodeInfo* nodeInfo;
	char query[4096];

        setlocale(LC_NUMERIC, "C");

	printf("%s: HomeId=%d Node=%d\n", (add)?"ValueAdded":"ValueChanged", homeID, nodeID );
	printf("Genre=%d\n", genre );
	printf("CommandClassId=%d\n", id );
	printf("Instance=%d\n", instanceID );
	printf("Index=%d\n", valueID.GetIndex() );
	printf("Label=%s\n", label.c_str() );
	printf("Units=%s\n", Manager::Get()->GetValueUnits( valueID ).c_str() );

        sprintf(query, "INSERT INTO notifications (homeid,node,genre,commandclass,instance,`index`,label,units,type,valueINT,valueSTRING,`year`) VALUES (");

	sprintf(query, "%s%d,%d",query,homeID,nodeID);
	sprintf(query, "%s,%d,%d",query,genre,id);
	sprintf(query, "%s,%d,%d",query,instanceID,valueID.GetIndex());
	sprintf(query, "%s,\'%s\',\'%s\'",query,label.c_str(), Manager::Get()->GetValueUnits( valueID ).c_str());

	nodeInfo = GetNodeInfo( _notification );
	if ( nodeInfo == NULL )
	{
	    return;
	}

	switch ( type )
	{
		case ValueID::ValueType_Bool:
		{
			Manager::Get()->GetValueAsBool( valueID, &bool_value );
			snprintf( dev_value, 1024, "%i", bool_value );
			printf( "Type=Bool (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'bool\',%s,NULL",query,dev_value);
			break;
		}
		case ValueID::ValueType_Byte:
		{
			Manager::Get()->GetValueAsByte( valueID, &byte_value );
			snprintf( dev_value, 1024, "%i", byte_value );
			printf( "Type=Byte (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'byte\',%s,NULL",query, dev_value);
			break;
		}
		case ValueID::ValueType_Decimal:
		{
			Manager::Get()->GetValueAsString( valueID, &decimal_value );
			snprintf( dev_value, 1024, "%s", strdup( decimal_value.c_str() ) );
			toDOT(dev_value);
			printf("Type=Decimal (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'decimal\',\'%s\',NULL",query,dev_value);
			break;
		}
		case ValueID::ValueType_Int:
		{
			Manager::Get()->GetValueAsInt( valueID, &int_value );
			snprintf( dev_value, 1024, "%d", int_value );
			printf("Type=Integer (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'integer\',%s,NULL",query,dev_value);
			break;
		}
		case ValueID::ValueType_Short:
		{
			Manager::Get()->GetValueAsShort( valueID, &short_value );
			snprintf( dev_value, 1024, "%d", short_value );
			printf("Type=Short (raw value=%s)\n", dev_value );
			toDOT(dev_value);
			sprintf(query, "%s,\'short\',\'%s\',NULL",query,dev_value);
			break;
		}
		case ValueID::ValueType_Schedule:
		{
			printf("Type=Schedule (not implemented)\n" );
			return;
			//break;
		}
		case ValueID::ValueType_String:
		{
			Manager::Get()->GetValueAsString( valueID, &string_value );
			snprintf( dev_value, 1024, "%s", strdup( string_value.c_str() ) );
			printf("Type=String (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'string\',NULL,\'%s\'",query, dev_value );
			break;
		}
		case ValueID::ValueType_Button:
		{
			printf("Type=Button (not implemented)\n" );
			return;
			//break;
		}
		case ValueID::ValueType_List:
		{
			Manager::Get()->GetValueListSelection( valueID, &list_value );
			snprintf( dev_value, 1024, "%s", strdup( list_value.c_str() ) );
			printf( "Type=List (raw value=%s)\n", dev_value );
			sprintf(query, "%s,\'list\',NULL,\'%s\'",query, dev_value);
			break;
		}
		default:
		printf( "Type=Unknown\n" );
		return;
	}

	sprintf(query, "%s,YEAR(NOW()))",query);

        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, "Could not insert row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
        }

	// zones - disabled

//	if (id == 113 && valueID.GetIndex() == 10)
//	{
//	    zones_validate(nodeID,homeID);
//	    printf(_("Zones validate for node %d"),nodeID);
//	}


	// Washer or dishwasher
	
	if (config.washer_node > 0 || config.dishwasher_node > 0)
	{
	    // index = 8
	    if (homeID == config.zwave_id && valueID.GetIndex() == 8 && id == 50 && (nodeID == config.washer_node || nodeID == config.dishwasher_node))
	    {
		double power = atof(dev_value);
		printf("power: %f, %s\n", power,dev_value);
		if (power == 0 && lastNodeWakeUpsHome != homeID && lastNodeWakeUps != nodeID) // ping or power off // ignore wake up
		{
		    if ((washer_status > 0 && washer_offcounter != -1 && nodeID == config.washer_node) || (dishwasher_status > 0 && dishwasher_offcounter != -1 && nodeID == config.dishwasher_node))
		    {

			if (nodeID == config.washer_node)
		        {
			    washer_status = 0;
			    washer_offcounter = 0;
			}
			else
			{
			    dishwasher_status = 0;
			    dishwasher_offcounter = 0;
			}
			
			// send alarm
			char info[4096];
			time_t rawtime;
			struct tm * timeinfo;
	
			time(&rawtime);
			timeinfo = localtime(&rawtime);

			if (nodeID == config.washer_node)
			{
				sprintf(info,_("[%s] - WASHER OFF - : Node %d Date %s "), config.prefix, nodeID, asctime(timeinfo));
				sprintf(query,"INSERT INTO nodesActionHistory (homeid,nodeId,timeStart,timeEnd,`value`) VALUES (%d,%d,\"%d-%d-%d %d:%d:%d\",NOW(),(SELECT `value` FROM powerUsage WHERE nodeId = %d))", homeID, nodeID, washer_timestart.tm_year+1900,washer_timestart.tm_mon+1,washer_timestart.tm_mday,washer_timestart.tm_hour,washer_timestart.tm_min,washer_timestart.tm_sec,nodeID);
			}
			else
			{
				sprintf(info,_("[%s] - DISHWASHER OFF - : Node %d Date %s "), config.prefix, nodeID, asctime(timeinfo));
				sprintf(query,"INSERT INTO nodesActionHistory (homeid,nodeId,timeStart,timeEnd,`value`) VALUES (%d,%d,\"%d-%d-%d %d:%d:%d\",NOW(),(SELECT `value` FROM powerUsage WHERE nodeId = %d))", homeID, nodeID, dishwasher_timestart.tm_year+1900,dishwasher_timestart.tm_mon+1,dishwasher_timestart.tm_mday,dishwasher_timestart.tm_hour,dishwasher_timestart.tm_min,dishwasher_timestart.tm_sec,nodeID);
			}

		        mysql_query(&mysql,query);
			int valpar = 0;
			setValueByAll( g_homeId, nodeID, 50, 1, 33, &valpar ); // reset

			if (strlen(config.gg_a1) > 0)
		    	    RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

			if (strlen(config.gg_a2) > 0)
			    RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);

		    }

		}


		if (power == 0)
		{
		    lastNodeWakeUps = 0; // don't wait for next wake up
		}
		if (power > 0)
		{

		    if ((power < 14 && washer_status == 3 && nodeID == config.washer_node) || (dishwasher_status == 3 && power < 1  && nodeID == config.dishwasher_node)) // maybe off
		    {

			if (nodeID == config.washer_node)
			    washer_offcounter++;
			else
			    dishwasher_offcounter++;

			if ((washer_offcounter > 10 && nodeID == config.washer_node) || (dishwasher_offcounter > 20 && nodeID == config.dishwasher_node)) // 10 actions under 15 so off?
			{
			    // send alarm
			    char info[4096];
			    time_t rawtime;
			    struct tm * timeinfo;
	
			    time(&rawtime);
			    timeinfo = localtime(&rawtime);

			    if (nodeID == config.washer_node)
				sprintf(info,_("[%s] - WASHER FINISH - : Node %d Date %s "), config.prefix, nodeID, asctime(timeinfo));
			    else
				sprintf(info,_("[%s] - DISHWASHER FINISH - : Node %d Date %s"), config.prefix, nodeID, asctime(timeinfo));

			    if (strlen(config.gg_a1) > 0)
		    	        RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

			    if (strlen(config.gg_a2) > 0)
			        RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);

			    //  fork for sms because too slow	
			    if (strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
			    {
				pthread_t sms_thread;
				pthread_create(&sms_thread, NULL, smsNow, &info);
				usleep(900000);
			    }


			    if (nodeID == config.washer_node)
			    {
			        washer_status = 0;
				washer_offcounter = -1;
			    }
			    else
			    {
			        dishwasher_status = 0;
				dishwasher_offcounter = -1;
			    }
			}
		    }
		    else
		    {
			if (nodeID == config.washer_node)
			    washer_offcounter=0;
			else
			    dishwasher_offcounter=0;
		    }

		    if (nodeID == config.washer_node)
		    {
			if (power > 100 && washer_status == 2) // working
			{
			    washer_status = 3;
			}
		    }
		    else
		    {
			if (power > 10 && dishwasher_status == 2) // working
			{
			    dishwasher_status = 3;
			}
		    }

		    if (power > 20 && ((washer_status == 1 && nodeID == config.washer_node) || (dishwasher_status == 1 && nodeID == config.dishwasher_node))) // yes, washer power on
		    {
			if (nodeID == config.washer_node)
			{
			    washer_status = 2;
			    washer_offcounter = 0;
			}
			else
			{
			    dishwasher_status = 2;
			    dishwasher_offcounter = 0;
			}

			// send alarm
			char info[4096];
			time_t rawtime;
			struct tm * timeinfo;
	
			time(&rawtime);
			timeinfo = localtime(&rawtime);

			if (nodeID == config.washer_node)
			{
			    washer_timestart = *localtime(&rawtime);
			    sprintf(info,_("[%s] - WASHER ON - : Node %d Date %s"), config.prefix, nodeID, asctime(timeinfo));
			}
			else
			{
			    dishwasher_timestart = *localtime(&rawtime);
			    sprintf(info,_("[%s] - DISHWASHER ON - : Node %d Date %s"), config.prefix, nodeID, asctime(timeinfo));
			}

			int valpar = 0;
			setValueByAll( g_homeId, nodeID, 50, 1, 33, &valpar );
			if (strlen(config.gg_a1) > 0)
		    	    RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

			if (strlen(config.gg_a2) > 0)
			    RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);
			
		    }

		    if (washer_status == 0 && nodeID == config.washer_node)
		    {
			washer_status = 1; // maybe on
		    }

		    if (dishwasher_status == 0 && nodeID == config.dishwasher_node)
		    {
			dishwasher_status = 1; // maybe on
		    }
		}
	    }
	}

	// Actions ZoneStart

	    char *to = new char[(strlen(dev_value) * 2) + 1];
	    mysql_real_escape_string(&mysql, to, dev_value, strlen(dev_value));
	    MYSQL_ROW row;

	    sprintf(query,"SELECT id, endNode, endValue, delayTimeMin, stampOnly, commandclassEnd, instanceEnd, indexEnd FROM zonesStart WHERE homeid = %d AND startNode = %d AND startValue = \"%s\" AND actiontimestart > NOW() AND NOW() < actiontimeend AND active = 1 AND commandclassStart = %d AND instanceStart = %d AND indexStart = %d", homeID, nodeID, to, id, instanceID, valueID.GetIndex());
	    int res = mysql_query(&mysql,query);
	    if (res == 0) {
		MYSQL_RES *result = mysql_store_result(&mysql);
//		printf("%s\n",query);
		int num_rows = mysql_num_rows(result);
		if (num_rows > 0 && res == 0)
		{
		    while ((row = mysql_fetch_row(result)))
	    	    {
			printf(_("Action zoneStart : %s\n"),row[0]);
			int stampOnly		= atoi(row[4]);
//			int delayTimeMin		= atoi(row[3]);
			int idTable			= atoi(row[0]);
			int endNode			= atoi(row[1]);
			int endValue		= atoi(row[2]);
			int commandClassEnd		= atoi(row[4]);
			int instanceEnd		= atoi(row[5]);
			int indexEnd		= atoi(row[6]);

			if (stampOnly == 0)
			{
			    bool res = setValueByAll(g_homeId, endNode, commandClassEnd, instanceEnd, indexEnd, &endValue);
    	    	    	    printf("ZONESTART = NODE %d : %d => %d\n", endNode, res, endValue);
			}

			sprintf(query,"UPDATE zonesStart SET lastAction = NOW() WHERE id = %d", idTable);
			mysql_query(&mysql,query);
		    }
    
	        }
		mysql_free_result(result);
	    }

	// Alarms

	if (strlen(config.gg_a1) > 0 || strlen(config.gg_a1) > 0 || strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
	{

	    if (strcmp(label.c_str(),"Flood") == 0 && strcmp(dev_value,"0") == 0 && alarmstatus == 1)
	    {

		bool res = setValue(g_homeId,config.alarm_node,0);
    	        printf("ALARM ON = NODE %d : %d\n",config.alarm_node, res);
    	        alarmstatus = 0;
	    }

	    if (strcmp(label.c_str(),"Flood") == 0 && strcmp(dev_value,"255") == 0)
	    {
		char info[4096];
		time_t rawtime;
		struct tm * timeinfo;
		
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		sprintf(info,_("[%s] - ALARM - : Node %d Date %s"), config.prefix, nodeID, asctime(timeinfo));

		if (strlen(config.gg_a1) > 0)
			RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

		if (strlen(config.gg_a2) > 0)
			RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);
		

		if (config.alarm_node > 0)
		{
		    sprintf(query,"SELECT parValue FROM parameters WHERE parName = 'alarmDisabled' LIMIT 1");
		    mysql_query(&mysql,query);
		    MYSQL_RES *result = mysql_store_result(&mysql);
		    MYSQL_ROW row;
		    row = mysql_fetch_row(result);
		    mysql_free_result(result);
		    printf(_("alarm node available\n"));
			// ALARM OPTION DISABLED?
		        if (atoi(row[0]) == 0)
		        {
			    printf(_("alarm enabled\n"));
			    sprintf(query,"SELECT id FROM zonesAlarms WHERE homeid = %d AND node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) ) ",homeID,nodeID);
			    mysql_query(&mysql,query);
			    result = mysql_store_result(&mysql);
			    int alarms = 0 ;
			    printf("%s\n",query);
			    while ((row = mysql_fetch_row(result)))
			    {
				printf(_("alarm zone : %s\n"),row[0]);
				sprintf(query,"UPDATE zonesAlarms SET zonesAlarms.timestamp = NOW(), zonesAlarms.alarms=zonesAlarms.alarms+1 WHERE id = %s LIMIT 1", row[0]);
			        mysql_query(&mysql,query);
			        alarms++;
			    }

			    mysql_free_result(result);
			    if (alarms > 0)
			    {
	    			bool res = setValue(g_homeId,config.alarm_node,1);
        	    	        printf(_("ALARM ON = NODE %d : %d\n"),config.alarm_node, res);
        	    	        alarmstatus = 1;
        	    	    }
        	        }
		}

		//  fork for sms because too slow
		if (strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
		{
			pthread_t sms_thread;
			pthread_create(&sms_thread, NULL, smsNow, &info);
			usleep(900000);
		}


	    }
	}


}

//-----------------------------------------------------------------------------
// <OnNotification>
// Callback that is triggered when a value, group or node changes
//-----------------------------------------------------------------------------

void OnNotification(Notification const* _notification, void* _context) {
    // Must do this inside a critical section to avoid conflicts with the main thread
    pthread_mutex_lock(&g_criticalSection);
printf("\n!!!!NOTIFICATION!!!!! : %d\n",_notification->GetType());
    switch (_notification->GetType()) {
        case Notification::Type_ValueAdded:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                // Add the new value to our list
                nodeInfo->m_values.push_back(_notification->GetValueID());
                RPC_ValueChanged((int)_notification->GetHomeId(), (int)_notification->GetNodeId(), _notification->GetValueID(), true, _notification);
            }
            break;
        }

        case Notification::Type_ValueRemoved:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                // Remove the value from out list
                for (list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it) {
                    if ((*it) == _notification->GetValueID()) {
                        nodeInfo->m_values.erase(it);
                        break;
                    }
                }
            }
            break;
        }

        case Notification::Type_ValueChanged:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                // One of the node values has changed
                // TBD...
                nodeInfo = nodeInfo;
            }
                RPC_ValueChanged((int)_notification->GetHomeId(), (int)_notification->GetNodeId(), _notification->GetValueID(), false, _notification);

            break;
        }

        case Notification::Type_Group:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                // One of the node's association groups has changed
                // TBD...
                nodeInfo = nodeInfo;
            }
            break;
        }

        case Notification::Type_NodeAdded:
        {
            // Add the new node to our list
            NodeInfo* nodeInfo = new NodeInfo();
            nodeInfo->m_homeId = _notification->GetHomeId();
            nodeInfo->m_nodeId = _notification->GetNodeId();
            nodeInfo->m_polled = false;
            g_nodes.push_back(nodeInfo);
            break;
        }

        case Notification::Type_NodeRemoved:
        {
            // Remove the node from our list
            uint32 const homeId = _notification->GetHomeId();
            uint8 const nodeId = _notification->GetNodeId();
            for (list<NodeInfo*>::iterator it = g_nodes.begin(); it != g_nodes.end(); ++it) {
                NodeInfo* nodeInfo = *it;
                if ((nodeInfo->m_homeId == homeId) && (nodeInfo->m_nodeId == nodeId)) {
                    g_nodes.erase(it);
                    break;
                }
            }
            break;
        }
	case Notification::Type_NodeProtocolInfo:
	{
	    printf("NODE PROTOCOL INFO\n");
	    //RPC_NodeProtocolInfo( (int)_notification->GetHomeId(), (int)_notification->GetNodeId(), _notification );
	    break;
	}

        case Notification::Type_NodeEvent:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                // We have received an event from the node, caused by a
                // basic_set or hail message.
                // TBD...               
                nodeInfo = nodeInfo;
		RPC_NodeEvent( (int)_notification->GetHomeId(), (int)_notification->GetNodeId(), _notification->GetValueID(), (int)_notification->GetEvent() );
            }
            printf("NODE EVENT!\n");
            break;
        }

        case Notification::Type_PollingDisabled:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                nodeInfo->m_polled = false;
            }
            break;
        }

        case Notification::Type_PollingEnabled:
        {
            if (NodeInfo * nodeInfo = GetNodeInfo(_notification)) {
                nodeInfo->m_polled = true;
            }
            break;
        }

        case Notification::Type_DriverReady:
        {
            g_homeId = _notification->GetHomeId();
            printf("READY\n");
            break;
        }


        case Notification::Type_DriverFailed:
        {
            g_initFailed = true;
            pthread_cond_broadcast(&initCond);
            break;
        }

        case Notification::Type_AwakeNodesQueried:
        case Notification::Type_AllNodesQueried:
        {
            pthread_cond_broadcast(&initCond);
	    Manager::Get()->WriteConfig( (int)_notification->GetHomeId() );
	    printf("AWAKE\n");
            break;
        }
        case Notification::Type_Notification:
        {
    	    printf("STATUS: %d = %d\n",_notification->GetNotification(),Notification::Code_Awake);
	    switch (_notification->GetNotification())
	    {
		case Notification::Code_Awake:
		{
		    RPC_WakeUp((int)_notification->GetHomeId(), (int)_notification->GetNodeId(),_notification);
		    
		    int start=1;
		    while (config.dynamic[start]>0)
		    {
			if ((int)_notification->GetNodeId() == config.dynamic[start])
			{
			    Manager::Get()->RequestNodeDynamic((int)_notification->GetHomeId(), (int)_notification->GetNodeId());
			}

			start++;
		    }
		    break;
		}
	    }
    	    break;
        }

        default:
        {
    	    printf("DEFAULT FUNC? %d \n",_notification->GetType());
        }
    }

    pthread_mutex_unlock(&g_criticalSection);
}

/******** DOSTUFF() *********************
 There is a separate instance of this function 
 for each connection.  It handles all communication
 once a connnection has been established.
 *****************************************/

void split(const string& s, char c, vector<string>& v) {
    string::size_type i = 0;
    string::size_type j = s.find(c);
    while (j != string::npos) {
        v.push_back(s.substr(i, j - i));
        i = ++j;
        j = s.find(c, j);
        if (j == string::npos)
            v.push_back(s.substr(i, s.length()));
    }
}

string trim(string s) {
    return s.erase(s.find_last_not_of(" \n\r\t") + 1);
}

//-----------------------------------------------------------------------------
// <get_configuration>
// get configuration for database
//-----------------------------------------------------------------------------


int get_configuration(struct config_type *config, char *path)
{
	FILE *fptr;
	char inputline[1000]	= "";
	char token[100]		= "";
	char val[100]		= "";
	char val2[100]		= "";
	char tmp[100]		= "";

	// First we set everything to defaults - faster than many if statements
	strcpy(config->mysql_host, "localhost");            // localhost, IP or domainname of server
	strcpy(config->mysql_user, "zwave");             // MySQL database user name
	strcpy(config->mysql_passwd, "zwave");          // Password for MySQL database user
	strcpy(config->mysql_database, "zwave");         // Name of MySQL database
	config->mysql_port = 0;                             // MySQL port. 0 means default port/socket
	config->log_level = 0;

	// open the config file

	fptr = NULL;
	if (path != NULL)
		fptr = fopen(path, "r");       //first try the parameter given
	if (fptr == NULL)                  //then try default search
	{
		if ((fptr = fopen("zwave.conf", "r")) == NULL)
		{
			if ((fptr = fopen("/usr/local/etc/zwave.conf", "r")) == NULL)
			{
				if ((fptr = fopen("/etc/zwave.conf", "r")) == NULL)
				{
					//Give up and use defaults
					return(-1);
				}
			}
		}
	}

	while (fscanf(fptr, "%[^\n]\n", inputline) != EOF)
	{
		sscanf(inputline, "%[^= \t]%*[ \t=]%s%*[, \t]%s%*[^\n]", token, val, val2);

		if (token[0] == '#')	// comment
			continue;

		if ((strcmp(token,"MYSQL_HOST") == 0) && (strlen(val) != 0))
		{
			strcpy(config->mysql_host, val);
			continue;
		}

		if ( (strcmp(token,"MYSQL_USERNAME") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->mysql_user, val);
			continue;
		}

		if ( (strcmp(token,"MYSQL_PASSWORD") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->mysql_passwd, val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_ALARM_NODE") == 0) && (strlen(val) != 0) )
		{
			config->alarm_node = atoi(val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_LIGHT_NODE") == 0) && (strlen(val) != 0) )
		{
			config->light_node = atoi(val);
			continue;
		}

		memset(tmp,0,99);
		strncpy(tmp,token,16);
		if ( (strcmp(tmp,"ZWAVE_POWER_NODE") == 0) && (strlen(val) != 0) )
		{
		    memset(tmp,0,99);
		    strncpy(tmp,token+16,strlen(token)-16);

			if (strlen(tmp)>0)
			{
			    int p = atoi(tmp);
			    if (p>0)
			    {
				config->power_node[p] = atoi(val);
			    }
			}
			continue;
		}

		memset(tmp,0,99);
		strncpy(tmp,token,16);
		if ( (strcmp(tmp,"ZWAVE_VALVE_NODE") == 0) && (strlen(val) != 0) )
		{
		    memset(tmp,0,99);
		    strncpy(tmp,token+16,strlen(token)-16);

			if (strlen(tmp)>0)
			{
			    int p = atoi(tmp);
			    if (p>0)
			    {
				config->valve_node[p] = atoi(val);
			    }
			}
			continue;
		}


		memset(tmp,0,99);
		strncpy(tmp,token,13);
		if ( (strcmp(tmp,"ZWAVE_DYNAMIC") == 0) && (strlen(val) != 0) )
		{
		    memset(tmp,0,99);
		    strncpy(tmp,token+13,strlen(token)-13);

			if (strlen(tmp)>0)
			{
			    int p = atoi(tmp);
			    if (p>0)
			    {
				config->dynamic[p] = atoi(val);
			    }
			}
			continue;
		}




		if ( (strcmp(token,"ZWAVE_WASHER") == 0) && (strlen(val) != 0) )
		{
			config->washer_node = atoi(val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_DISHWASHER") == 0) && (strlen(val) != 0) )
		{
			config->dishwasher_node = atoi(val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_DOOR_NODE") == 0) && (strlen(val) != 0) )
		{
			config->door_node = atoi(val);
			continue;
		}


		if ( (strcmp(token,"PREFIX") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->prefix, val);
			continue;
		}

		if ( (strcmp(token,"TV_SAMSUNG_IP") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_ip, val);
			continue;
		}

		if ( (strcmp(token,"TV_SMART") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_smart, val);
			continue;
		}

		if ( (strcmp(token,"TV_LOGIN") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_login, val);
			continue;
		}

		if ( (strcmp(token,"TV_PASS") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_pass, val);
			continue;
		}

		if ( (strcmp(token,"TV_START") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_start, val);
			continue;
		}

		if ( (strcmp(token,"TV_OFF") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_off, val);
			continue;
		}

		if ( (strcmp(token,"TV_SAMSUNG_PORT") == 0) && (strlen(val) != 0) )
		{
			config->tv_port = atoi(val);
			continue;
		}

		if ( (strcmp(token,"GG_UID") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->gg_uid, val);
			continue;
		}

		if ( (strcmp(token,"GG_ALARMTO1") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->gg_a1, val);
			continue;
		}

		if ( (strcmp(token,"GG_ALARMTO2") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->gg_a2, val);
			continue;
		}

		if ( (strcmp(token,"GG_PASSWORD") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->gg_passwd, val);
			continue;
		}

		if ( (strcmp(token,"MYSQL_DATABASE") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->mysql_database, val);
			continue;
		}
		
		if ( (strcmp(token,"MYSQL_PORT") == 0) && (strlen(val) != 0) )
		{
			config->mysql_port = atoi(val);
			continue;
		}

		if ((strcmp(token,"LOG_LEVEL")==0) && (strlen(val)!=0))
		{
			config->log_level = atoi(val);
			continue;
		}

		if ( (strcmp(token,"SMS_COMMANDS") == 0) && (strlen(val) != 0) )
		{
			config->sms_commands = atoi(val);
			continue;
		}

		if ( (strcmp(token,"SMS_LOCATION") == 0) && (strlen(val) != 0) )
		{
			config->sms_location = atoi(val);
			continue;
		}

		if ( (strcmp(token,"SMS_PHONE1") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->sms_phone1, val);
			continue;
		}

		if ( (strcmp(token,"SMS_PHONE2") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->sms_phone2, val);
			continue;
		}

		if ( (strcmp(token,"SMS_DEVICE") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->sms_device, val);
			continue;
		}

		if ( (strcmp(token,"SMS_CONNECTION") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->sms_connection, val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_DEVICE") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->zwave_device, val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_ID") == 0) && (strlen(val) != 0) )
		{
			config->zwave_id = atoi(val);
			continue;
		}


	}

	return (0);
}


void OnControllerUpdate( Driver::ControllerState cs, Driver::ControllerError error, void *ct )
{

	// Possible ControllerState values:
	// ControllerState_Normal     - No command in progress.
	// ControllerState_Waiting    - Controller is waiting for a user action.
	// ControllerState_InProgress - The controller is communicating with the other device to carry out the command.
	// ControllerState_Completed  - The command has completed successfully.
	// ControllerState_Failed     - The command has failed.
	// ControllerState_NodeOK     - Used only with ControllerCommand_HasNodeFailed to indicate that the controller thinks the node is OK.
	// ControllerState_NodeFailed - Used only with ControllerCommand_HasNodeFailed to indicate that the controller thinks the node has failed.

	pthread_mutex_lock( &g_criticalSection );

	switch (cs) {
		case Driver::ControllerState_Normal:
		{
			printf(_("ControllerState Event: no command in progress") );
			break;
		}
		case Driver::ControllerState_Waiting:
		{
			printf(_("ControllerState Event: waiting for a user action") );
			break;
		}
		case Driver::ControllerState_InProgress:
		{
			printf(_("ControllerState Event: communicating with the other device") );
			break;
		}
		case Driver::ControllerState_Completed:
		{
			printf(_("ControllerState Event: command has completed successfully") );
			break;
		}
		case Driver::ControllerState_Failed:
		{
			printf(_("ControllerState Event: command has failed") );
			break;
		}
		case Driver::ControllerState_NodeOK:
		{
			printf(_("ControllerState Event: the node is OK"));

			// Store Node State

			break;
		}
		case Driver::ControllerState_NodeFailed:
		{
			printf(_("ControllerState Event: the node has failed") );

			// Store Node State

			break;
		}
		default:
		{
			printf(_("ControllerState Event:  unknown response") );
			break;
		}
	}

    pthread_mutex_unlock(&g_criticalSection);

}

void
timerHandler(sigval_t t )
{
    char query[4096];
    MYSQL_RES *result;
    int num_rows;
    MYSQL_ROW row;

    printf("\nTIMER GOING\n");

    pthread_mutex_lock(&g_criticalSection);

    sprintf(query,"SELECT zonesPower.powernode,zonesPower.value FROM zonesPower LEFT JOIN switches ON (switches.node = zonesPower.powernode AND switches.homeid = zonesPower.homeid) WHERE TIME(NOW()) > actiontimestart AND TIME(NOW()) < actiontimeend AND zonesPower.result <> switches.status AND zonesPower.active = 1");

        if(mysql_query(&mysql, query))
        {
                printf(_("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
	}
	else
	{
	    result = mysql_store_result(&mysql);
	    num_rows = mysql_num_rows(result);
	    if (num_rows > 0)
	    {
		while ((row = mysql_fetch_row(result)))
	        {
		    printf("POWERNODE %d SET VALUE %d\n",atoi(row[0]),atoi(row[1]));
		    setValue(g_homeId,atoi(row[0]),atoi(row[1]));
		}
	    }
	    else
	    {
		printf(_("TIMER: [ZONESPOWER] Nothing to do\n"));
	    }

	    mysql_free_result(result);
	}

////////////////////////////////////

    sprintf(query,"SELECT zonesThermo.thermonode,zonesThermo.value FROM zonesThermo LEFT JOIN thermostat ON (thermostat.node = zonesThermo.thermonode AND thermostat.homeid = zonesThermo.homeid) WHERE TIME(NOW()) > actiontimestart AND TIME(NOW()) < actiontimeend AND zonesThermo.value <> thermostat.temp AND zonesThermo.active = 1");

        if(mysql_query(&mysql, query))
        {
                printf(_("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
	}
	else
	{
	    result = mysql_store_result(&mysql);
	    num_rows = mysql_num_rows(result);
	    if (num_rows > 0)
	    {
		while ((row = mysql_fetch_row(result)))
	        {
		    printf("THERMONODE %d SET VALUE %d\n",atoi(row[0]),atoi(row[1]));
		    setPoint(g_homeId,atoi(row[0]),row[1]);
		}
	    }
	    else
	    {
		printf("TIMER: [THERMO] Nothing to do\n");
	    }

	    mysql_free_result(result);
	}



////////////////////////////////////

    if (strlen(config.tv_ip) > 6)
    {
	if (ping(config.tv_ip))
	{
	    // OFF
//	    pthread_mutex_lock(&g_criticalSection);
    	    sprintf(query,"INSERT INTO other (object,status,timestamp) VALUES ('TV',0,NOW()) ON DUPLICATE KEY UPDATE status = 0, other.timestamp = NOW()");
	    mysql_query(&mysql, query);
//            pthread_mutex_unlock(&g_criticalSection);
    	}
	else
	{
	    // ON
//	    pthread_mutex_lock(&g_criticalSection);
    	    sprintf(query,"INSERT INTO other (object,status,timestamp) VALUES ('TV',1,NOW()) ON DUPLICATE KEY UPDATE status = 1, other.timestamp = NOW()");
	    mysql_query(&mysql, query);
//            pthread_mutex_unlock(&g_criticalSection);
    	}
    }

 /////////////////////////////////////


    sprintf(query,"SELECT tv_no,tv_action,tv_keys,tv_id FROM tv WHERE ((HOUR(NOW()) > tv_hour ) OR (tv_hour = HOUR(NOW()) AND MINUTE(NOW()) >= tv_minutes)) AND tv_weekday = WEEKDAY(NOW())+1 AND (tv_lastaction != DATE(NOW()) OR tv_lastaction IS NULL) AND tv.tv_active = 1");

        if(mysql_query(&mysql, query))
        {
                printf(_("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
	}
	else
	{
	    result = mysql_store_result(&mysql);
	    num_rows = mysql_num_rows(result);
	    if (num_rows > 0)
	    {
		while ((row = mysql_fetch_row(result)))
	        {
		    printf("TVNODE %d SET VALUE %s WITH KEYS %s\n",atoi(row[0]), row[1], row[2]);
		    tvManager(row[1],row[2]);
		    sprintf(query,"UPDATE tv SET tv_lastaction = NOW() WHERE tv_id = %d LIMIT 1", atoi(row[3]));
	            mysql_query(&mysql,query);
		}
	    }
	    else
	    {
		printf(_("TIMER: [TV] Nothing to do\n"));
	    }

	    mysql_free_result(result);
	}

 /////////////////////////////////////

    sprintf(query,"SELECT node FROM `stateGet` where homeid = %d AND NOW() > DATE_ADD(lastupdate, INTERVAL updateEveryMinutes MINUTE)",config.zwave_id);

        if(mysql_query(&mysql, query))
        {
                printf(_("Could not select row. %s %d: \%s \n"), query, mysql_errno(&mysql), mysql_error(&mysql));
	}
	else
	{
	    result = mysql_store_result(&mysql);
	    num_rows = mysql_num_rows(result);
	    if (num_rows > 0)
	    {
		while ((row = mysql_fetch_row(result)))
	        {
		    printf("NODE %d REFRESH NOW\n",atoi(row[0]));
		    Manager::Get()->RequestNodeState( g_homeId, atoi(row[0]) );
		    sprintf(query,"UPDATE stateGet SET lastupdate = NOW() WHERE node = %d LIMIT 1", atoi(row[0]));
	            mysql_query(&mysql,query);
		}
	    }
	    else
	    {
		printf(_("TIMER: [STATE] Nothing to do\n"));
	    }

	    mysql_free_result(result);
	}


 /////////////////////////////////////////

	    sprintf(query,"SELECT zS.id, zS.endNode, zS.endValue, zS.delayTimeMin, zS.stampOnly, zS.commandclassEnd, zS.instanceEnd, zS.indexEnd, zS.parentRule, COUNT(z1.id) AS zSum1, COUNT(z2.id) AS zSum2 FROM zonesStart AS zS LEFT JOIN zonesStart AS z1 ON (z1.ruleId = zS.parentRule) LEFT JOIN zonesStart AS z2 ON (z2.ruleId = zS.parentRule AND z2.lastAction IS NOT NULL) WHERE zS.homeid = %d AND zS.actiontimestart > NOW() AND NOW() < zS.actiontimeend AND zS.active = 1 AND zS.delayTimeMin IS NOT NULL AND zS.stampOnly = 1 AND zS.lastAction IS NOT NULL AND NOW() > (zS.lastAction +  INTERVAL zS.delayTimeMin MINUTE) GROUP BY zS.id", g_homeId);
	    int res = mysql_query(&mysql,query);
	    if (res == 0) 
	    {

		MYSQL_RES *result = mysql_store_result(&mysql);

		int num_rows = mysql_num_rows(result);

	        if (num_rows > 0)
		{
		    while ((row = mysql_fetch_row(result)))
		    {
			printf(_("Action zoneStart : %s\n"),row[0]);
//		        int stampOnly		= atoi(row[4]);
//		        int delayTimeMin	= atoi(row[3]);
		        int idTable		= atoi(row[0]);
		        int endNode		= atoi(row[1]);
		        int endValue		= atoi(row[2]);
		        int commandClassEnd	= atoi(row[4]);
		        int instanceEnd		= atoi(row[5]);
			int indexEnd		= atoi(row[6]);
			int parentRule		= atoi(row[7]);
			int parentsC1		= atoi(row[8]);
			int parentsC2		= atoi(row[9]);

			if (parentsC1 == parentsC2) {
			    bool res = setValueByAll(g_homeId, endNode, commandClassEnd, instanceEnd, indexEnd, &endValue);
    	    	    	    printf("ZONESTART = NODE %d : %d => %d\n", endNode, res, endValue);
			
			    if (parentRule > 0)
				sprintf(query,"UPDATE zonesStart SET lastAction = NULL WHERE id = %d OR ruleId = %d", idTable, parentRule);
			    else
				sprintf(query,"UPDATE zonesStart SET lastAction = NULL WHERE id = %d", idTable, parentRule);
			    mysql_query(&mysql,query);
			}


		    }

		}

		mysql_free_result(result);
	    }

    pthread_mutex_unlock(&g_criticalSection);

 /////////////////////////////////////////
 /* Auto Alarm */

    pthread_mutex_lock(&g_criticalSection);

    sprintf(query,"SELECT parValue FROM parameters WHERE parName = 'autoAlarm' LIMIT 1");
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);
    row = mysql_fetch_row(result);

printf("parValue: %d\n",atoi(row[0]));

    if (atoi(row[0]) == 1)
    {
	int lastTime = 0;
	int alarmOn = 0;
        char *garbage = NULL;

	mysql_free_result(result);
	sprintf(query,"SELECT parValue, ROUND(TIMESTAMPDIFF(SECOND,parTimestamp,NOW()) / 60) FROM parameters WHERE parName = 'alarmOn' LIMIT 1");
        mysql_query(&mysql,query);
	result = mysql_store_result(&mysql);

	if (row[1])
        	lastTime = strtol(row[1],&garbage,0);

	if (row[0])
	    alarmOn = strtol(row[0],&garbage,0);

	printf("parValue: %d, %d\n",alarmOn, lastTime);

	if (alarmOn == 0)
	{
	    mysql_free_result(result);
	    sprintf(query,"SELECT ROUND(TIMESTAMPDIFF(SECOND,MAX(onState),NOW()) / 60) FROM basicLastState AS b1 WHERE b1.nodeid IN (SELECT id FROM nodes WHERE alarmNode = 1)");
    	    mysql_query(&mysql,query);
	    result = mysql_store_result(&mysql);
	    num_rows = mysql_num_rows(result);


	    if (num_rows > 0)
	    {
		row = mysql_fetch_row(result);

	    printf("onState: %d\n",atoi(row[0]));
		if ((atoi(row[0]) > 20 && atoi(row[0]) < 23))
		{
		    sprintf(query,"SELECT COUNT(b2.nodeid) FROM basicLastState AS b1 LEFT JOIN basicLastState AS b2 ON (b2.onState > b1.onState OR b2.offState > b2.offState) WHERE b1.nodeid IN (SELECT id FROM nodes WHERE alarmNode = 1) AND b2.nodeid NOT IN (SELECT id FROM nodes WHERE ignoreNode = 1)");
		    mysql_query(&mysql,query);
		    MYSQL_RES *result = mysql_store_result(&mysql);
		    num_rows = mysql_num_rows(result);
		    if (num_rows > 0)
		    {
			row = mysql_fetch_row(result);
			    printf("Count: %d\n",atoi(row[0]));
			if (atoi(row[0]) == 0)
			{
			    sprintf(query,"UPDATE parameters SET parValue = 1 WHERE parName = 'alarmOn' LIMIT 1");
    			    mysql_query(&mysql,query);

			    char info[4096];
			    time_t rawtime;
			    struct tm * timeinfo;
		
			    time(&rawtime);
			    timeinfo = localtime(&rawtime);
			    sprintf(info,_("[%s] - ALARM - : LOCK activated - Date %s"), config.prefix, asctime(timeinfo));


			    pthread_mutex_unlock(&g_criticalSection);

			    alarm(info);

			    pthread_mutex_lock(&g_criticalSection);

			}
		    }

		}
	    }

	    mysql_free_result(result);
	}else{
	    mysql_free_result(result);

	    // check nodes

		    sprintf(query,"SELECT COUNT(nodeid) FROM basicLastState WHERE onState < NOW() AND onState > DATE_SUB(NOW(), INTERVAL 15 MINUTE) AND nodeid NOT IN (SELECT id FROM nodes WHERE ignoreNode = 1) ");
		    mysql_query(&mysql,query);
		    MYSQL_RES *result = mysql_store_result(&mysql);
		    num_rows = mysql_num_rows(result);
		    if (num_rows > 0 && lastTime > 22)
		    {
			row = mysql_fetch_row(result);
			if (atoi(row[0]) > 1)
			{
			    sprintf(query,"UPDATE parameters SET parValue = 0 WHERE parName = 'alarmOn' LIMIT 1");
			    mysql_query(&mysql,query);

			    char info[4096];
			    time_t rawtime;
			    struct tm * timeinfo;
		
			    time(&rawtime);
			    timeinfo = localtime(&rawtime);
			    sprintf(info,_("[%s] - ALARM - : LOCK deactivated - %d nodes - Date %s"), config.prefix, atoi(row[0]), asctime(timeinfo));


			    pthread_mutex_unlock(&g_criticalSection);

			    alarm(info);

			    pthread_mutex_lock(&g_criticalSection);

			}
		    }

		    mysql_free_result(result);

	}



    }else{
	mysql_free_result(result);
    }


    pthread_mutex_unlock(&g_criticalSection);

 /////////////////////////////////////////



	// /etc/zwave.conf enable/disable
	if (config.sms_commands == 1)
	{
	    RPC_LoadSMS(stateMachine);
	}

}

static int makeTimer(char *name, timer_t *timerID, int expireMS, int intervalMS )
{
    struct sigevent         te;
    struct itimerspec       its;
    int status;

     /* Set and enable alarm */
    te.sigev_notify		= SIGEV_THREAD; //SIGNAL;
    te.sigev_value.sival_ptr	= timerID;
    te.sigev_notify_function 	= timerHandler;
    te.sigev_notify_attributes	= NULL;
    status = timer_create(CLOCK_REALTIME, &te, timerID);
    if (status == -1)
	printf("ERROR1\n");

    its.it_interval.tv_sec	= intervalMS;
    its.it_interval.tv_nsec	= 0;
    its.it_value.tv_sec		= expireMS;
    its.it_value.tv_nsec	= 0;
    status = timer_settime(*timerID, 0, &its, 0);
    if (status == -1)
	printf("ERROR2\n");

    return(0);
}



//-----------------------------------------------------------------------------
// <main>
// Create the driver and then wait
//-----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_t mutexattrSMS;

    int forked = fork();

    if (forked != 0)
	return 0;

	washer_status		= 0;
	washer_offcounter	= -1;
	
	dishwasher_status	= 0;
	dishwasher_offcounter	= -1;


    setlocale(LC_ALL,"MinOZW");
    bindtextdomain("","/usr/share/locale");
    textdomain("MinOZW");

    get_configuration(&config, argv[1]);

    if(!mysql_init(&mysql))
    {
        fprintf(stderr, _("Cannot initialize MySQL"));
        exit(0);
    }

    if(!mysql_real_connect(&mysql, config.mysql_host, config.mysql_user,
                           config.mysql_passwd, config.mysql_database,
                           config.mysql_port, NULL, 0))
    {
                fprintf(stderr, "%d: %s \n",
                mysql_errno(&mysql), mysql_error(&mysql));
                exit(0);
    }

    /* Allocates state machine */
    stateMachine = GSM_AllocStateMachine();

    if (stateMachine == NULL) {
                fprintf(stderr, "GSM_AllocStateMachine failed \n");
		exit(0);
    }

    cfg = GSM_GetConfig(stateMachine, 0);

    free(cfg->Device);
    cfg->Device = strdup(config.sms_device);

    free(cfg->Connection);
    cfg->Connection = strdup(config.sms_connection);

    /* We have one valid configuration */
    GSM_SetConfigNum(stateMachine, 1);


    pthread_mutexattr_init(&mutexattrSMS);
    pthread_mutexattr_settype(&mutexattrSMS, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutexattr_setpshared(&mutexattrSMS, PTHREAD_PROCESS_SHARED);

    pthread_mutex_init(&g_criticalSectionSMS, &mutexattrSMS);
    pthread_mutexattr_destroy(&mutexattrSMS);


    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_criticalSection, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);

    pthread_mutex_lock(&initMutex);


    // Create the OpenZWave Manager.
    // The first argument is the path to the config files (where the manufacturer_specific.xml file is located
    // The second argument is the path for saved Z-Wave network state and the log file.  If you leave it NULL 
    // the log file will appear in the program's working directory.
    Options::Create("../../../../config/", "", "");
	Options::Get()->AddOptionInt( "SaveLogLevel", LogLevel_Detail );
	Options::Get()->AddOptionInt( "QueueLogLevel", LogLevel_Debug );
	Options::Get()->AddOptionInt( "DumpTrigger", LogLevel_Error );
	Options::Get()->AddOptionInt( "PollInterval", 60 );
	Options::Get()->AddOptionBool( "IntervalBetweenPolls", true );
	Options::Get()->AddOptionBool("ValidateValueChanges", false);
    Options::Get()->Lock();

    Manager::Create();

    // Add a callback handler to the manager.  The second argument is a context that
    // is passed to the OnNotification method.  If the OnNotification is a method of
    // a class, the context would usually be a pointer to that class object, to
    // avoid the need for the notification handler to be a static.
    Manager::Get()->AddWatcher(OnNotification, NULL);

    // Add a Z-Wave Driver
    // Modify this line to set the correct serial port for your PC interface.

	string port = config.zwave_device; // "/dev/ttyS21";
	if ( argc > 1 )
	{
		port = argv[1];
	}
	if( strcasecmp( port.c_str(), "usb" ) == 0 )
	{
		Manager::Get()->AddDriver( "HID Controller", Driver::ControllerInterface_Hid );
	}
	else
	{
		Manager::Get()->AddDriver( port );
	}

    // Now we just wait for the driver to become ready, and then write out the loaded config.
    // In a normal app, we would be handling notifications and building a UI for the user.

printf("Waiting ...\n");
//sleep(5);
    pthread_cond_wait(&initCond, &initMutex);
printf("Going ...\n");
    if (!g_initFailed) {


        Manager::Get()->WriteConfig(g_homeId);





//	xmlrpc_int32 generic = Manager::Get()->GetNodeGeneric( g_homeId, 5 );
//	xmlrpc_int32 specific = Manager::Get()->GetNodeSpecific( g_homeId, 5 );

//	printf("generic: %d, specific: %d\n",generic,specific);


        Driver::DriverData data;
        Manager::Get()->GetDriverStatistics(g_homeId, &data);

		printf("SOF: %d ACK Waiting: %d Read Aborts: %d Bad Checksums: %d\n", data.m_SOFCnt, data.m_ACKWaiting, data.m_readAborts, data.m_badChecksum);
		printf("Reads: %d Writes: %d CAN: %d NAK: %d ACK: %d Out of Frame: %d\n", data.m_readCnt, data.m_writeCnt, data.m_CANCnt, data.m_NAKCnt, data.m_ACKCnt, data.m_OOFCnt);
		printf("Dropped: %d Retries: %d\n", data.m_dropped, data.m_retries);


        printf("***************************************************** \n");
        printf("6004 ZWaveCommander Server \n");

        //Manager::Get()->SetNodeName(g_homeId, 3, "Lampshade");


    // Start timer
        makeTimer((char *)"ACTIONS", &firstTimerID, 60, 60);

        try {
            // Create the socket
            ServerSocket server(6004);
            while (true) {

                //pthread_mutex_lock(&g_criticalSection);
                // Do stuff            
                ServerSocket new_sock;
                server.accept(new_sock);
                try {
                    while (true) {


                        std::string data;
                        new_sock >> data;

                        //get zwave commands

                        //if (trim(data.c_str()) == "BYE") exit(0);

		if (trim(data.c_str()) == "ALARMON")
		{
		     bool res = setValue(g_homeId,config.alarm_node,1);
                    printf("ALARM ON = NODE %d : %d\n",config.alarm_node, res);
		}

		if (trim(data.c_str()) == "ALARMOFF")
		{
		    bool res = setValue(g_homeId,config.alarm_node,0);
                    printf("ALARM OFF = NODE %d \n",config.alarm_node, res);
		}

		if (trim(data.c_str()) == "LIGHTON1")
		{
		     bool res = setValue(g_homeId,config.light_node,255);
                    printf("LIGHT ON = NODE %d : %d\n",config.light_node, res);
		}

		if (trim(data.c_str()) == "LIGHTOFF1")
		{
		    bool res = setValue(g_homeId,config.light_node,0);
                    printf("LIGHT OFF = NODE %d \n",config.light_node, res);
		}

		if (trim(data.substr(0,8).c_str()) == "VALVEOFF")
		{

		    string tmp = data.substr(8,data.length()-8);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0 && mynode < 255)
		        {
			    if (config.valve_node[mynode] > 0)
			    {
				bool res = setValue(g_homeId,config.valve_node[mynode],0);
                	        printf("VALVE OFF = NODE %d \n",config.valve_node[mynode], res);
                	    }
                	}
                    }
		}

		if (trim(data.substr(0,7).c_str()) == "VALVEON")
		{

		    string tmp = data.substr(7,data.length()-7);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0 && mynode < 255)
		        {
			    if (config.valve_node[mynode] > 0)
			    {
				bool res = setValue(g_homeId,config.valve_node[mynode],255);
                	        printf("VALVE ON = NODE %d \n",config.valve_node[mynode], res);
                	    }
                	}
                    }
		}


		if (trim(data.c_str()) == "TVOFF")
		{
		    tvManager((char *) "TVOFF",(char *) "");
                    printf("TV OFF\n");
		}

		if (trim(data.c_str()) == "TVON")
		{
		    tvManager((char *) "TVON",(char *) "");
                    printf("TVON\n");
		}

		if (trim(data.c_str()) == "TVKEYTV")
		{
		    tvManager((char *) "TVKEYTV",(char *) "");
                    printf("TVKEYTV\n");
		}

		if (trim(data.substr(0,7).c_str()) == "POWERON")
		{
		    string tmp = data.substr(7,data.length()-7);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0 && mynode < 255)
			{
			    if (config.power_node[mynode] > 0)
			    {
				bool res = setValue(g_homeId,config.power_node[mynode],255);
                		printf("POWER ON = NODE %d : %d\n",config.power_node[mynode], res);
                	    }
                	}
                    }
		}

		if (trim(data.substr(0,8).c_str()) == "POWEROFF")
		{

		    string tmp = data.substr(8,data.length()-8);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0 && mynode < 255)
		        {
			    if (config.power_node[mynode] > 0)
			    {
				bool res = setValue(g_homeId,config.power_node[mynode],0);
                	        printf("POWER OFF = NODE %d \n",config.power_node[mynode], res);
                	    }
                	}
                    }
		}

		if (trim(data.substr(0,5).c_str()) == "STATE")
		{
		    string tmp = data.substr(5,data.length()-5);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0)
				Manager::Get()->RequestNodeState( g_homeId, mynode );
		    }
		}


		if (trim(data.substr(0,7).c_str()) == "REFRESH")
		{
		    string tmp = data.substr(7,data.length()-7);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0)
			    Manager::Get()->RefreshNodeInfo( g_homeId, mynode );
		    }
		}

		if (trim(data.substr(0,6).c_str()) == "UPDATE")
		{
		    string tmp = data.substr(6,data.length()-6);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0)
			    Manager::Get()->BeginControllerCommand( g_homeId, Driver::ControllerCommand_RequestNodeNeighborUpdate, OnControllerUpdate, NULL, false, mynode, 0 );
		    }
		}

		if (trim(data.c_str()) == "SAVECONFIG")
		{
		        Manager::Get()->WriteConfig(g_homeId);
		}

		if (trim(data.substr(0,8).c_str()) == "DELROUTE")
		{
		    string tmp = data.substr(8,data.length()-8);
		    char *garbage = NULL;
		    if (tmp.length() > 0)
		    {
			int mynode = strtol(tmp.c_str(),&garbage,0);
		        if (mynode > 0)
				Manager::Get()->BeginControllerCommand( g_homeId, Driver::ControllerCommand_DeleteAllReturnRoutes, OnControllerUpdate, NULL, true, mynode, 0 );
		    }
		}

		// NEWROUTE2,4 -> Node 2 to node 4
		if (trim(data.substr(0,8).c_str()) == "NEWROUTE")
		{
		    string tmp = data.substr(8,data.length()-8);
		    if (tmp.length() > 0)
		    {
			    int nodeF	= 0;
			    int nodeT	= 0;
			    sscanf(tmp.c_str(), "%d,%d", &nodeF, &nodeT);
		        if (nodeF > 0 && nodeT > 0)
			    Manager::Get()->BeginControllerCommand( g_homeId, Driver::ControllerCommand_AssignReturnRoute, OnControllerUpdate, NULL, true, nodeF, nodeT );
		    }
		}

		// CONF2,27,18 -> Node 2, Parameter 27, Value 18
		if (trim(data.substr(0,4).c_str()) == "CONF")
		{
			string tmp = data.substr(4,data.length()-4);

    			if (tmp.length() > 0)
			{
			    int node	= 0;
			    int par	= 0;
			    int valpar	= 0;
			    sscanf(tmp.c_str(), "%d,%d,%d", &node, &par, &valpar);
        	    	    pthread_mutex_lock(&g_criticalSection);
				Manager::Get()->SetConfigParam(g_homeId, node, par, valpar);
			    pthread_mutex_unlock(&g_criticalSection);

		    	    printf("Node %d Parameter %d to %d\n",node,par,valpar);
			}
		}

		// COMMS2,18,4,0,Off -> Node 2, Value 18, Instance 4, Index 0, value = Off -> Send only to instance
		if (trim(data.substr(0,5).c_str()) == "COMMS")
		{
			string tmp = data.substr(5,data.length()-5);

    			if (tmp.length() > 0)
			{
			    int node	= 0;
			    char valpar[256];
			    int instance= 0;
			    int id	= 0;
			    int index	= 0;
			    int size	= 0;

			    sscanf(tmp.c_str(), "%d,%d,%d,%d,%[^\t\n]", &node, &id, &instance, &index, valpar);
			    size = strnlen((const char*)valpar,255);
			    if (size > 1)
			    {
				valpar[size-1]=0;
			    }
		
				setValueByAll(g_homeId, node, id, instance, index, &valpar);

                	        printf("COMMS = NODE %d CLASS %d INSTANCE %d INDEX %d SET \"%s\" (%d) \n",node, id, instance, index, valpar, size);

			}
		}

		// COMMI2,18,4,0,5 -> Node 2, Value 18, Instance 4, Index 0, value = 5 -> Send only to instance
		if (trim(data.substr(0,5).c_str()) == "COMMI")
		{
			string tmp = data.substr(5,data.length()-5);

    			if (tmp.length() > 0)
			{
			    int node	= 0;
			    int valpar = 0;
			    int instance= 0;
			    int id	= 0;
			    int index	= 0;

			    sscanf(tmp.c_str(), "%d,%d,%d,%d,%d", &node, &id, &instance, &index, &valpar);
				setValueByAll(g_homeId, node, id, instance, index, &valpar);

                	        printf("COMMI = NODE %d CLASS %d INSTANCE %d INDEX %d SET %d \n",node, id, instance, index, valpar);

			}
		}


		// BASICI2,18,4 -> Node 2, Value 18, Instance 4 -> Send only to instance
		if (trim(data.substr(0,6).c_str()) == "BASICI")
		{
			string tmp = data.substr(6,data.length()-6);

    			if (tmp.length() > 0)
			{
			    int node	= 0;
			    int valpar	= 0;
			    int instance= 0;
			    sscanf(tmp.c_str(), "%d,%d,%d", &node, &valpar, &instance);
				setValueByInstance(g_homeId,node,&valpar,instance);
                	        printf("BASICI = NODE %d SET %d \n",node, valpar);

			}
		}

		// BASICA2,18 -> Node 2, Value 18 -> Send to all instances
		if (trim(data.substr(0,6).c_str()) == "BASICA")
		{
			string tmp = data.substr(6,data.length()-6);

    			if (tmp.length() > 0)
			{
			    int node	= 0;
			    int valpar	= 0;
			    sscanf(tmp.c_str(), "%d,%d", &node, &valpar);
				setValue(g_homeId,node,valpar);
                	        printf("BASICA = NODE %d SET %d \n",node, valpar);

			}
		}


		if (trim(data.c_str()) == "SET")
		{
        	        pthread_mutex_lock(&g_criticalSection);
/*
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 3);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 2);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 4);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 7);
*/
    Manager::Get()->AddAssociation(g_homeId, 3, 2, 19);
    Manager::Get()->AddAssociation(g_homeId, 2, 2, 19);
    Manager::Get()->AddAssociation(g_homeId, 4, 2, 19);
    Manager::Get()->AddAssociation(g_homeId, 7, 2, 19);

/*
			Manager::Get()->SetConfigParam(g_homeId, 13, 101, 225); // 11100001=1+32+64+128=225
			Manager::Get()->SetConfigParam(g_homeId, 13, 2, 0); // wakeup after batt
			Manager::Get()->SetConfigParam(g_homeId, 13, 3, 35); // off action after 35s
			Manager::Get()->SetConfigParam(g_homeId, 13, 111, 600); // data after 600s
*/
///			Manager::Get()->SetConfigParam(g_homeId, 18, 132, 900); // wakeup after batt

////			Manager::Get()->SetConfigParam(g_homeId, 9, 112, 1); // data after 600s



	if ( NodeInfo* nodeInfo = GetNodeInfo( g_homeId, 18 ) )
	{
		// Find the correct instance
		for ( list<ValueID>::iterator it = nodeInfo->m_values.begin(); it != nodeInfo->m_values.end(); ++it )
		{
			int id = (*it).GetCommandClassId();
			//int inst = (*it).GetInstance();
			int index = (*it).GetIndex();
			if (id == 0x84 && index == 0)
			{
				    int int_value = 900;
				    Manager::Get()->SetValue( *it, int_value );

			    printf("Command class: %d\n",id);
			}

			if (id == 0x84 && index == 4)
			{
				    int int_value = 900;
				    Manager::Get()->SetValue( *it, int_value );

			    printf("Command class: %d\n",id);
			}

		}
	}

		        pthread_mutex_unlock(&g_criticalSection);

		        Manager::Get()->WriteConfig(g_homeId);


		}

		if (trim(data.c_str()) == "SMSTEST")
		{
		    char info[4096];
		    sprintf(info, "TEST SMS");

			pthread_t sms_thread;
			pthread_create(&sms_thread, NULL, smsNow, &info);

		}

                        //give list of devices
                        if (trim(data.c_str()) == "ALIST") {
                            string device;
                            for (list<NodeInfo*>::iterator it = g_nodes.begin(); it != g_nodes.end(); ++it) {
                                NodeInfo* nodeInfo = *it;
                                int nodeID = nodeInfo->m_nodeId;
                                string nodeType = Manager::Get()->GetNodeType(g_homeId, nodeInfo->m_nodeId);
                                string nodeName = Manager::Get()->GetNodeName(g_homeId, nodeInfo->m_nodeId);
                                string nodeZone = Manager::Get()->GetNodeLocation(g_homeId, nodeInfo->m_nodeId);

                                if (nodeName.size() == 0) nodeName = "Undefined";

                                if (nodeType != "Static PC Controller") {
                                    stringstream ssNodeName, ssNodeId, ssNodeType, ssNodeZone;
                                    ssNodeName << nodeName;
                                    ssNodeId << nodeID;
                                    ssNodeType << nodeType;
                                    ssNodeZone << nodeZone;
                                    device += "DEVICE~" + ssNodeName.str() + "~" + ssNodeId.str() + "~"+ ssNodeZone.str() +"~" + ssNodeType.str() + "#";
                                }
                            }
                            device = device.substr(0, device.size() - 1) + "\n";                           
                            printf("Sent Device List \n");
                            new_sock << device;
                        }

                        vector<string> v;
                        split(data, '~', v);

                        string command, deviceType;

                        if (v.size() > 0) {
                            //check Type of Command
                            stringstream sCommand;
                            sCommand << v[0].c_str();
                            string command = sCommand.str();
                            
                            printf("Command: %s", command.c_str());
                            if (command == "DEVICE") {
                                //check type
                                deviceType = v[v.size() - 1];

                                int Node = 0;
                                int Level = 0;
                                string Type = "";

                                Level = atoi(v[2].c_str());
                                Node = atoi(v[1].c_str());
                                Type = v[3].c_str();
                                Type = trim(Type);

                                if ((Type == "Multilevel Switch") || (Type == "Multilevel Power Switch")) {
                                    pthread_mutex_lock(&g_criticalSection);
                                    Manager::Get()->SetNodeLevel(g_homeId, Node, Level);
                                    pthread_mutex_unlock(&g_criticalSection);
                                }

                                if (Type == "Binary Switch") {
                                    pthread_mutex_lock(&g_criticalSection);
                                    if (Level == 0) {
                                        Manager::Get()->SetNodeOff(g_homeId, Node);

                                    } else {
                                        Manager::Get()->SetNodeOn(g_homeId, Node);
                                    }
                                    pthread_mutex_unlock(&g_criticalSection);
                                }

                                stringstream ssNode, ssLevel;
                                ssNode << Node;
                                ssLevel << Level;
                                string result = "MSG~ZWave Node=" + ssNode.str() + " Level=" + ssLevel.str() + "\n";
                                new_sock << result;
                            }

                            if (command == "SETNODE") {
                                int Node = 0;
                                string NodeName = "";
                                string NodeZone = "";
                                
                                Node = atoi(v[1].c_str());
                                NodeName = v[2].c_str();
                                NodeName = trim(NodeName);
                                NodeZone = v[3].c_str();
                                
                                pthread_mutex_lock(&g_criticalSection);
                                Manager::Get()->SetNodeName(g_homeId, Node, NodeName);
                                Manager::Get()->SetNodeLocation(g_homeId, Node, NodeZone);
                                pthread_mutex_unlock(&g_criticalSection);
                                
                                stringstream ssNode, ssName, ssZone;
                                ssNode << Node;
                                ssName << NodeName;
                                ssZone << NodeZone;
                                string result = "MSG~ZWave Name set Node=" + ssNode.str() + " Name=" + ssName.str() + " Zone=" + ssZone.str() + "\n";
                                new_sock << result;
                                
                                //save details to XML
                                Manager::Get()->WriteConfig(g_homeId);
                            }

                            //  sleep(5);
                        }


                    }
                } catch (SocketException&) {
                }
                //pthread_mutex_unlock(&g_criticalSection);
                //sleep(5);
            }
        } catch (SocketException& e) {
            std::cout << "Exception was caught: " << e.description() << "\nExiting.\n";
        }
    }

    /* Free up used memory */
    GSM_FreeStateMachine(stateMachine);

    Manager::Get()->RemoveWatcher( OnNotification, NULL );
    Manager::Destroy();
    Options::Destroy();
    pthread_mutex_destroy(&g_criticalSection);
    pthread_mutex_destroy(&g_criticalSectionSMS);
    return 0;
}
