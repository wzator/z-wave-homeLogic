#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int show_remote_processes(ssh_session session)
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

    rc = channel_request_exec(channel, "ps aux");
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

    if (fgets(buf, sizeof(buf), stdin) == NULL)
    {
	free(hash);
	return -1;
    }
    if (strncasecmp(buf, "yes", 3) != 0)
    {
	free(hash);
        return -1;
    }

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


int main()
{
    ssh_session my_ssh_session;
    int rc;
    char *password;

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
	exit(-1);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to localhost: %s\n",
        ssh_get_error(my_ssh_session));
	ssh_free(my_ssh_session);
        exit(-1);
    }

    // Verify the server's identity
    // For the source code of verify_knowhost(), check previous example
    if (verify_knownhost(my_ssh_session) < 0)
    {
	ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
	exit(-1);
    }

    // Authenticate ourselves
    password = getpass("Password: ");
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
        ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
	exit(-1);
    }

    show_remote_processes(my_ssh_session);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
}

