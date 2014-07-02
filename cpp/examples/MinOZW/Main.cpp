//-----------------------------------------------------------------------------
//
//	Main.cpp v0.20140116
//
//	Based on minimal application to test OpenZWave.
//
//
//	Copyright (c) 2013-2014 Wojciech Zatorski <wojciech@zatorski.net>
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

#define PACKETSIZE  64

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
	int    alarm_node;
	int    light_node;
	int    power_node[255];
	int    valve_node;
	int    door_node;
	char   tv_ip[64];
	int    tv_port;
	int    dynamic[256];
	int    washer_node;
};

// Value-Defintions of the different String values

static list<NodeInfo*> g_nodes;
static pthread_mutex_t g_criticalSection;
static pthread_cond_t initCond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t initMutex = PTHREAD_MUTEX_INITIALIZER;

// GSM

volatile GSM_Error sms_send_status;
volatile gboolean gshutdown = FALSE;

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
	perror("getprotobyname errror");
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
        perror("Set TTL option");
        close(sd);
        return 1;
    }
    if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 )
    {
        perror("Request nonblocking I/O");
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
        for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = cnt++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
        if ( sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
            perror("sendto");

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
	printf("Sent SMS on device: \"%s\"\n", GSM_GetConfig(sm, -1)->Device);
	if (status==0) {
		printf("..OK");
		sms_send_status = ERR_NONE;
	} else {
		printf("..error %i", status);
		sms_send_status = ERR_UNKNOWN;
	}
	printf(", message reference=%d\n", MessageReference);
}

/* Function to handle errors */
void error_handler(GSM_Error error, GSM_StateMachine *s)
{
	if (error != ERR_NONE) {
		printf("ERROR: %s\n", GSM_ErrorString(error));
		if (GSM_IsConnected(s))
			GSM_TerminateConnection(s);
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



int RPC_SendSMS(char *recipient_number, char *message_text)
{
// GSM

	GSM_StateMachine *s;
	GSM_Config *cfg;
	GSM_Error error;

	GSM_SMSMessage sms;
	GSM_SMSC PhoneSMSC;
	GSM_Debug_Info *debug_info;
	int return_value = 0;

	/* Register signal handler */
	signal(SIGINT, interrupt);
	signal(SIGTERM, interrupt);

	/*
	 * We don't need gettext, but need to set locales so that
	 * charset conversion works.
	 */
	GSM_InitLocales(NULL);

	/* Enable global debugging to stderr */
	debug_info = GSM_GetGlobalDebug();
	GSM_SetDebugFileDescriptor(stderr, TRUE, debug_info);
	GSM_SetDebugLevel("textall", debug_info);

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

	/* Allocates state machine */
	s = GSM_AllocStateMachine();
	if (s == NULL)
		return 3;

	/*
	 * Enable state machine debugging to stderr
	 * Same could be achieved by just using global debug config.
	 */
	debug_info = GSM_GetDebug(s);
	GSM_SetDebugGlobal(FALSE, debug_info);
	GSM_SetDebugFileDescriptor(stderr, TRUE, debug_info);
	GSM_SetDebugLevel("textall", debug_info);

	// Get pointer to config structure
	cfg = GSM_GetConfig(s, 0);

	free(cfg->Device);
	cfg->Device = strdup(config.sms_device);

	free(cfg->Connection);
	cfg->Connection = strdup(config.sms_connection);

	/* We have one valid configuration */
	GSM_SetConfigNum(s, 1);

	/* Connect to phone */
	/* 1 means number of replies you want to wait for */
	error = GSM_InitConnection(s, 1);
	error_handler(error,s);

	/* Set callback for message sending */
	/* This needs to be done after initiating connection */
	GSM_SetSendSMSStatusCallback(s, send_sms_callback, NULL);

	/* We need to know SMSC number */
	PhoneSMSC.Location = 1;
	error = GSM_GetSMSC(s, &PhoneSMSC);
	error_handler(error,s);

	/* Set SMSC number in message */
	CopyUnicodeString(sms.SMSC.Number, PhoneSMSC.Number);

	/*
	 * Set flag before callind SendSMS, some phones might give
	 * instant response
	 */
	sms_send_status = ERR_TIMEOUT;

	/* Send message */
	error = GSM_SendSMS(s, &sms);
	error_handler(error,s);

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
	error_handler(error,s);

	/* Free up used memory */
	GSM_FreeStateMachine(s);

	return return_value;
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
        if (write(1, buffer, nbytes) != nbytes)
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
    char buf[10];

    state = ssh_is_server_known(session);
    hlen = ssh_get_pubkey_hash(session, &hash);

    if (hlen < 0)
        return -1;
    switch (state)
    {
    case SSH_SERVER_KNOWN_OK:
	break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        fprintf(stderr, "For security reasons, connection will be stopped\n");
	free(hash);
	return -1;
    case SSH_SERVER_FOUND_OTHER:
	fprintf(stderr, "The host key for this server was not found but an other"
	"type of key exists.\n");
	fprintf(stderr, "An attacker might change the default server key to"
	"confuse your client into thinking the key does not exist\n");
	free(hash);
	return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
	fprintf(stderr, "Could not find known host file.\n");
	fprintf(stderr, "If you accept the host key here, the file will be"
	"automatically created.\n");
	/* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
	hexa = ssh_get_hexa(hash, hlen);
	fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
	fprintf(stderr, "Public key hash: %s\n", hexa);
	free(hexa);

    if (ssh_write_knownhost(session) < 0)
    {
	fprintf(stderr, "Error %s\n", strerror(errno));
        free(hash);
	return -1;
    }

    break;
    case SSH_SERVER_ERROR:
	fprintf(stderr, "Error %s", ssh_get_error(session));
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
        fprintf(stderr, "Error connecting to localhost: %s\n",
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
        fprintf(stderr, "Error authenticating with password: %s\n",
        ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
	return(-1);
    }

    show_remote_processes(my_ssh_session, command);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
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
		printf("Nie udało się połączyć: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	if (gg_notify(sess, NULL, 0) == -1) {	/* serwery gg nie pozwalaja wysylac wiadomosci bez powiadomienia o userliscie (przetestowane p.protocol_version [0x15; def] */
		printf("Połączenie przerwane: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	if (gg_send_message(sess, GG_CLASS_MSG, number, (unsigned char*) text) == -1) {
		printf("Połączenie przerwane: %s\n", strerror(errno));
		gg_free_session(sess);
		return 1;
	}

	/* poniższą część można olać, ale poczekajmy na potwierdzenie */

	while (0) {
		if (!(e = gg_watch_fd(sess))) {
			printf("Połączenie przerwane: %s\n", strerror(errno));
			gg_logoff(sess);
			gg_free_session(sess);
			return 1;
		}

		if (e->type == GG_EVENT_ACK) {
			printf("Wysłano.\n");
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

			    printf("Command class: %d\n",id);
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


/* ALARMS ***************************************** */

//-----------------------------------------------------------------------------
// <alarm>
// 
//-----------------------------------------------------------------------------


void alarm(char *info)
{
		if (strlen(config.gg_a1) > 0)
			RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

		if (strlen(config.gg_a2) > 0)
			RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);

		if (strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
		{
		    signal(SIGCHLD, SIG_IGN); // don't wait for children
		    int forked = fork();

    		    if (forked == 0)
    		    {

			if (strlen(config.sms_phone1) > 0)
		    	    RPC_SendSMS(config.sms_phone1, info);

			if (strlen(config.sms_phone2) > 0)
			    RPC_SendSMS(config.sms_phone2, info);
		
			_exit(3);
		    }
		}

}


//-----------------------------------------------------------------------------
// <zones_validate>
// 
//-----------------------------------------------------------------------------

void zones_validate(int nodeId)
{
    char query[4096];
    char info[1024];

    MYSQL_RES *result;
    int num_fields;
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

	sprintf(info,"- MOVE AUTO - : Node %d Date %s", nodeId, asctime(timeinfo));
	printf(info);
	alarm(info);
	return ;
    }

    sprintf(query,"SELECT COUNT(*) AS cdx FROM zonesFree WHERE zonesFree.date = DATE(NOW())");
    mysql_query(&mysql,query);
    result	= mysql_store_result(&mysql);
    row		= mysql_fetch_row(result);
    int skipZones = atoi(row[0]);
    mysql_free_result(result);

    sprintf(query,"SELECT COUNT(*) AS cdx FROM zones WHERE node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) )  AND active = 1", nodeId);
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);
    num_fields = mysql_num_fields(result);

    row = mysql_fetch_row(result);

    if (atoi(row[0]) > 0 && skipZones < 1)
    {
		time_t rawtime;
		struct tm * timeinfo;
		
		time(&rawtime);
		timeinfo = localtime(&rawtime);
    
		sprintf(info,"- MOVE - : Node %d Date %s", nodeId, asctime(timeinfo));
		printf(info);
		alarm(info);
	
    }
    else
    {
	printf("No move [%d]\n", row[0]);
    }

    mysql_free_result(result);

    sprintf(query,"SELECT id FROM zonesAction WHERE node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) )  AND DATE(zonesAction.timestamp) != DATE(NOW())",nodeId);
    mysql_query(&mysql,query);
    result = mysql_store_result(&mysql);
    num_fields = mysql_num_fields(result);

    while ((row = mysql_fetch_row(result)))
    {
	sprintf(query,"UPDATE zonesAction SET zonesAction.timestamp = NOW(), zonesAction.query=zonesAction.query+1 WHERE id = %s LIMIT 1", row[0]);
        mysql_query(&mysql,query);

		time_t rawtime;
		struct tm * timeinfo;
		
		time(&rawtime);
		timeinfo = localtime(&rawtime);
    
		sprintf(info,"- ONE MOVE - : Node %d Date %s", nodeId, asctime(timeinfo));
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
                fprintf(stderr, "Could not insert row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
        }

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
        int num_fields;
        MYSQL_ROW row;

	// Instance can never be zero, we need to be backwards compatible
	if ( instanceID == 0 ) {
		instanceID = 1;
	}

	printf("BASIC_CLASS: HomeId=%d Node=%d\n", homeID, nodeID );

	snprintf( dev_value, 1024, "%d", value );

        sprintf(query, "INSERT INTO basic (homeid,node,instance,valueINT,parentId) VALUES (");

	if (value == 0)
	    sprintf(query, "%s%d,%d,%d,\'%s\',(SELECT MAX(id) FROM basic AS b WHERE node = %d AND valueINT > 0)",query,homeID,nodeID,instanceID,dev_value,nodeID);
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
                fprintf(stderr, "Could not insert row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
        }

/* lights management */

	if (atoi(dev_value) > 0) /* sensorNode ON */
	{
	    sprintf(query,"SELECT lightNode,id,dependsOnNode,dependsLastAction FROM zonesLights WHERE sensorNode = %d AND TIME(NOW()) >= timeStart AND TIME(NOW()) <= timeEnd AND active = 1 ", nodeID);
	    sprintf(startedQry,"1");
	}
	else
	{
	    sprintf(query,"SELECT lightNode,id,dependsOnNode,dependsLastAction FROM zonesLights WHERE ((sensorNode = %d AND endNode IS NULL) OR (endNode = %d AND startedQry IS NOT NULL)) AND active = 1 AND TIME(NOW()) >= timeStart AND TIME(NOW()) <= timeEnd", nodeID, nodeID);
	    sprintf(startedQry,"NULL");
	}

        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, "Could not select row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
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
		if (row[1])
		    myNodes[i][1]=strtol(row[1],&garbage,0);
		if (row[2])
		    myNodes[i][2]=strtol(row[2],&garbage,0);
		if (row[3])
		    myNodes[i][3]=strtol(row[3],&garbage,0);
		i++;
	    }

	    mysql_free_result(result);

	    for (int a=0; a<i; a++)
	    {
		int skip = 0;
		if (myNodes[a][2] > 1)
		{
		    int lastTime = myNodes[a][3];
		    sprintf(query,"(SELECT ROUND(TIME_TO_SEC(TIMEDIFF(NOW(),basic.timestamp)) / 60) AS nodeTime, valueINT, basic.timestamp  FROM basic WHERE node = %d ORDER BY basic.timestamp DESC LIMIT 1) UNION (SELECT ROUND(TIME_TO_SEC(TIMEDIFF(NOW(),switches.timestamp)) / 60) AS nodeTime, status, switches.timestamp  FROM switches WHERE node = %d ORDER BY switches.timestamp DESC LIMIT 1)", myNodes[a][2],myNodes[a][2]);
    		    if(mysql_query(&mysql, query))
    		    {
    		        fprintf(stderr, "Could not select row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
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
	    	    		        printf("Skip Node %d from %d (time %s/%s last time %d : %s)\n",myNodes[a][0],myNodes[a][2],rowL[0],rowL[1],lastTime,rowL[2]);
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
		    bool res = setValue(g_homeId,myNodes[a][0],atoi(dev_value));
		    printf("zonesLights SET %d = %d\n",myNodes[a][0],atoi(dev_value));
		}
	    }

	}

/* **************** */

	/* for alarms when 255 is returned */
	if (value == 255)
	{
	    zones_validate(nodeID);
	    printf("Zones validate for node %d",nodeID);
	}

}



//-----------------------------------------------------------------------------
// <RPC_ValueChanhed>
// Function that is triggered when a value, group or node changes
//-----------------------------------------------------------------------------

void RPC_ValueChanged( int homeID, int nodeID, ValueID valueID, bool add, Notification const* _notification )
{
	int id = valueID.GetCommandClassId();
	int genre = valueID.GetGenre();
	string label = Manager::Get()->GetValueLabel( valueID );
	int instanceID = valueID.GetInstance();
	int type = valueID.GetType();
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

	printf("%s: HomeId=%d Node=%d\n", (add)?"ValueAdded":"ValueChanged", homeID, nodeID );
	printf("Genre=%d\n", genre );
	printf("CommandClassId=%d\n", id );
	printf("Instance=%d\n", instanceID );
	printf("Index=%d\n", valueID.GetIndex() );
	printf("Label=%s\n", label.c_str() );
	printf("Units=%s\n", Manager::Get()->GetValueUnits( valueID ).c_str() );

        sprintf(query, "INSERT INTO notifications (homeid,node,genre,commandclass,instance,`index`,label,units,type,valueINT,valueSTRING) VALUES (");

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

	sprintf(query, "%s)",query);

        if(mysql_query(&mysql, query))
        {
                fprintf(stderr, "Could not insert row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
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
		sprintf(info,"- ALARM - : Node %d Date %s ", nodeID, asctime(timeinfo));

		if (strlen(config.gg_a1) > 0)
			RPC_SendGG(atoi(config.gg_a1), (unsigned char *) info);

		if (strlen(config.gg_a2) > 0)
			RPC_SendGG(atoi(config.gg_a2), (unsigned char *) info);
		

		if (config.alarm_node > 0)
		{
		    sprintf(query,"SELECT parValue FROM parameters WHERE parName = 'alarmDisabled' LIMIT 1");
		    mysql_query(&mysql,query);
		    MYSQL_RES *result = mysql_store_result(&mysql);
		    int num_fields = mysql_num_fields(result);
		    MYSQL_ROW row;
		    row = mysql_fetch_row(result);
		    mysql_free_result(result);
		    printf("alarm node available\n");
			// ALARM OPTION DISABLED?
		        if (atoi(row[0]) == 0)
		        {
		    	    printf("alarm enabled\n");
			    sprintf(query,"SELECT id FROM zonesAlarms WHERE node = %d AND dayOfWeek = WEEKDAY(NOW())+1 AND (HOUR(NOW()) > startHour OR (HOUR(NOW())=startHour AND MINUTE(NOW())>=startMinutes)) AND (HOUR(NOW()) < endHour OR ( HOUR(NOW()) = endHour AND MINUTE(NOW())<endMinutes  ) ) ",nodeID);
			    mysql_query(&mysql,query);
			    result = mysql_store_result(&mysql);
			    num_fields = mysql_num_fields(result);
			    int alarms = 0 ;
			    printf("%s\n",query);
			    while ((row = mysql_fetch_row(result)))
			    {
				printf("alarm zone : %s\n",row[0]);
				sprintf(query,"UPDATE zonesAlarms SET zonesAlarms.timestamp = NOW(), zonesAlarms.alarms=zonesAlarms.alarms+1 WHERE id = %s LIMIT 1", row[0]);
			        mysql_query(&mysql,query);
			        alarms++;
			    }

			    mysql_free_result(result);
			    if (alarms > 0)
			    {
	    			bool res = setValue(g_homeId,config.alarm_node,1);
        	    	        printf("ALARM ON = NODE %d : %d\n",config.alarm_node, res);
        	    	        alarmstatus = 1;
        	    	    }
        	        }
		}

		//  fork for sms because too slow
		if (strlen(config.sms_phone1) > 0 || strlen(config.sms_phone2) > 0)
		{
		    signal(SIGCHLD, SIG_IGN); // don't wait for children
		    int forked = fork();

    		    if (forked == 0)
    		    {

			if (strlen(config.sms_phone1) > 0)
		    	    RPC_SendSMS(config.sms_phone1, info);

			if (strlen(config.sms_phone2) > 0)
			    RPC_SendSMS(config.sms_phone2, info);
		
			_exit(3);
		    }
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

		if ( (strcmp(token,"ZWAVE_DOOR_NODE") == 0) && (strlen(val) != 0) )
		{
			config->door_node = atoi(val);
			continue;
		}

		if ( (strcmp(token,"ZWAVE_VALVE_NODE") == 0) && (strlen(val) != 0) )
		{
			config->valve_node = atoi(val);
			continue;
		}

		if ( (strcmp(token,"TV_SAMSUNG_IP") == 0) && (strlen(val) != 0) )
		{
			strcpy(config->tv_ip, val);
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
			printf("ControllerState Event: no command in progress" );
			break;
		}
		case Driver::ControllerState_Waiting:
		{
			printf("ControllerState Event: waiting for a user action" );
			break;
		}
		case Driver::ControllerState_InProgress:
		{
			printf("ControllerState Event: communicating with the other device" );
			break;
		}
		case Driver::ControllerState_Completed:
		{
			printf("ControllerState Event: command has completed successfully" );
			break;
		}
		case Driver::ControllerState_Failed:
		{
			printf("ControllerState Event: command has failed" );
			break;
		}
		case Driver::ControllerState_NodeOK:
		{
			printf("ControllerState Event: the node is OK");

			// Store Node State

			break;
		}
		case Driver::ControllerState_NodeFailed:
		{
			printf("ControllerState Event: the node has failed" );

			// Store Node State

			break;
		}
		default:
		{
			printf("ControllerState Event:  unknown response" );
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

    sprintf(query,"SELECT zonesPower.powernode,zonesPower.value FROM zonesPower LEFT JOIN switches ON (switches.node = zonesPower.powernode) WHERE TIME(NOW()) > actiontimestart AND TIME(NOW()) < actiontimeend AND zonesPower.result <> switches.status AND zonesPower.active = 1");

        if(mysql_query(&mysql, query))
        {
                printf("Could not select row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
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
		    bool res = setValue(g_homeId,atoi(row[0]),atoi(row[1]));
		}
	    }
	    else
	    {
		printf("TIMER: [ZONESPOWER] Nothing to do\n");
	    }

	    mysql_free_result(result);
	}

////////////////////////////////////

    sprintf(query,"SELECT zonesThermo.thermonode,zonesThermo.value FROM zonesThermo LEFT JOIN thermostat ON (thermostat.node = zonesThermo.thermonode) WHERE TIME(NOW()) > actiontimestart AND TIME(NOW()) < actiontimeend AND zonesThermo.value <> thermostat.temp AND zonesThermo.active = 1");

        if(mysql_query(&mysql, query))
        {
                printf("Could not select row. %s %d: \%s \n", query, mysql_errno(&mysql), mysql_error(&mysql));
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
		    bool res = setPoint(g_homeId,atoi(row[0]),row[1]);
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

        pthread_mutex_unlock(&g_criticalSection);


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

    int forked = fork();

    if (forked != 0)
	return 0;



    get_configuration(&config, argv[1]);

    if(!mysql_init(&mysql))
    {
        fprintf(stderr, "Cannot initialize MySQL");
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

		if (trim(data.c_str()) == "VALVEON1")
		{
		     bool res = setValue(g_homeId,config.valve_node,255);
                    printf("VALVE ON = NODE %d : %d\n",config.valve_node, res);
		}

		if (trim(data.c_str()) == "VALVEOFF1")
		{
		    bool res = setValue(g_homeId,config.valve_node,0);
                    printf("VALVE OFF = NODE %d \n",config.valve_node, res);
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

		if (trim(data.c_str()) == "DELROUTE9")
		{
		    Manager::Get()->BeginControllerCommand( g_homeId, Driver::ControllerCommand_DeleteAllReturnRoutes, OnControllerUpdate, NULL, true, 9, 0 );
		}

		if (trim(data.c_str()) == "NEWROUTE9")
		{
		    Manager::Get()->BeginControllerCommand( g_homeId, Driver::ControllerCommand_AssignReturnRoute, OnControllerUpdate, NULL, true, 9, 6 );
		}

		if (trim(data.c_str()) == "SET")
		{
        	        pthread_mutex_lock(&g_criticalSection);
/*
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 3);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 2);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 4);
    Manager::Get()->RemoveAssociation(g_homeId, 10, 1, 7);

    Manager::Get()->AddAssociation(g_homeId, 3, 2, 10);
    Manager::Get()->AddAssociation(g_homeId, 2, 2, 10);
    Manager::Get()->AddAssociation(g_homeId, 4, 2, 10);
    Manager::Get()->AddAssociation(g_homeId, 7, 2, 10);
*/
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

	    	    signal(SIGCHLD, SIG_IGN); // don't wait for children

		    int forked = fork();

    		    if (forked == 0)
    		    {

			if (strlen(config.sms_phone1) > 0)
		    	    RPC_SendSMS(config.sms_phone1, info);

			if (strlen(config.sms_phone2) > 0)
			    RPC_SendSMS(config.sms_phone2, info);
		
			_exit(3);
		    }
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

    Manager::Get()->RemoveWatcher( OnNotification, NULL );
    Manager::Destroy();
    Options::Destroy();
    pthread_mutex_destroy(&g_criticalSection);
    return 0;
}
