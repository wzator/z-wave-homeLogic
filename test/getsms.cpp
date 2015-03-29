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
#include "libgadu.h"
#include "gammu.h"
#include <signal.h>

volatile GSM_Error sms_send_status;
volatile gboolean gshutdown = FALSE;

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
	int    valve_node[255];
	int    door_node;
	char   tv_ip[64];
	char   tv_smart[64];
	char   tv_login[50];
	char   tv_pass[50];
	char   tv_start[256];
	char   tv_off[256];
	int    tv_port;
	int    dynamic[256];
	int    washer_node;
	int    dishwasher_node;
	int    sms_commands;
};


struct config_type config;


void error_handler(GSM_Error error, GSM_StateMachine *s)
{
	if (error != ERR_NONE) {
		printf("ERROR: %s / %d\n", GSM_ErrorString(error), error);
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


int RPC_LoadSMS()
{
// GSM
	GSM_Debug_Info *debug_info;
	gboolean start;
	GSM_SMSMessage 	smsD;
	GSM_MultiSMSMessage sms;
	GSM_StateMachine *s;
	GSM_Config *cfg;
	GSM_Error error;
	int i;
        GSM_SMSFolders folders;

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

	printf("Device: %s\n",config.sms_device);
	printf("Connection: %s\n", config.sms_connection);

	free(cfg->Connection);
	cfg->Connection = strdup(config.sms_connection);

	/* We have one valid configuration */
	GSM_SetConfigNum(s, 1);

	printf("Configuration loaded\n");

	/* Connect to phone */
	/* 1 means number of replies you want to wait for */
	error = GSM_InitConnection(s, 1);
	error_handler(error,s);

	printf("Initialized connection\n");
	error = GSM_GetSMSFolders(s, &folders);
	error_handler(error,s);
	memset(&sms, 0, sizeof(sms));
	memset(&smsD, 0, sizeof(smsD));


	/* Read all messages */
	error = ERR_NONE;
	start = TRUE;

	for (int a=0; a<10; a++)
	{
	sms.Number = 0;
	sms.SMS[0].Location = a;
	sms.SMS[0].Folder = 0;

	error=GSM_GetSMS(s, &sms);

	if (sms.Number != 0)
	{
	    printf("Number: %d\n",sms.Number);
	    printf("Location: %d, Folder: %d\n", sms.SMS[0].Location, sms.SMS[0].Folder);
	    printf("Number: \"%s\"\n", DecodeUnicodeConsole(sms.SMS[0].Number));

	    char text[256];
		if (sms.SMS[i].Coding == SMS_Coding_8bit) {
			printf("8-bit message, can not display\n");
		} else {
			sprintf(text,"%s", DecodeUnicodeConsole(sms.SMS[0].Text));
			printf("Text: \"%s\"\n", DecodeUnicodeConsole(sms.SMS[0].Text));
		}

	    smsD.Location = a;
	    smsD.Folder = 0;
	   GSM_DeleteSMS(s, &smsD);
	}
	}
	/* Terminate connection */
	error = GSM_TerminateConnection(s);
	error_handler(error,s);

	/* Free up used memory */
	GSM_FreeStateMachine(s);

	return 0;

}

int main(int argc, char *argv[])
{
    get_configuration(&config, argv[1]);

    RPC_LoadSMS();
}
