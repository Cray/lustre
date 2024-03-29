#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <glob.h>
#include <getopt.h>

#include "lsupport.h"
#include "err_util.h"

static int start_daemon(char *auth_req)
{
	int rc;

	rc = system("/usr/bin/systemctl restart lsvcgss");
	if (rc < 0 || (errno = WEXITSTATUS(rc))) {
		printerr(LL_ERR, "systemctl restart lsvcgss service failed: %s\n",
			 strerror(errno));
		rc = -errno;
	} else {
		printerr(LL_INFO, "lsvcgss service automatically restarted\n");
		rc = 0;
	}

	return rc;
}

int main(int argc, char **argv)
{
	int local_socket;
	struct sockaddr_un addr;
	ssize_t bytes_sent;
	char *auth_req = NULL, *cachename = NULL;
	ssize_t req_len;
	int opt, debug = 0, tried_daemon = 0, rc = 0;

	/* Parameters received from kernel (see rsi_do_upcall()):
	 * -c <cache name> -r <auth request> -d
	 * -d checks connection to lsvcgssd daemon
	 */

	static struct option long_opts[] = {
		{ .name = "cache",   .has_arg = required_argument, .val = 'c'},
		{ .name = "debug",   .has_arg = no_argument,	   .val = 'd'},
		{ .name = "authreq", .has_arg = required_argument, .val = 'r'},
		{ .name = NULL, } };

	/* init gss logger for foreground (stderr) or background (syslog) */
	initerr(NULL, LL_MAX, isatty(STDOUT_FILENO));

	while ((opt = getopt_long(argc, argv, "c:dr:",
				  long_opts, NULL)) != EOF) {
		switch (opt) {
		case 'c':
			cachename = optarg;
			break;
		case 'd':
			debug = 1;
			goto socket;
		case 'r':
			auth_req = optarg;
			break;
		default:
			printerr(LL_ERR, "error: unknown option: '%c'\n", opt);
			return EXIT_FAILURE;
		}
	}

	if (optind != argc) {
		printerr(LL_ERR,
			 "error: extraneous arguments provided, check usage\n");
		return EXIT_FAILURE;
	}

	if (!cachename || !auth_req) {
		printerr(LL_ERR, "error: missing arguments, check usage\n");
		return EXIT_FAILURE;
	}

	if (strcmp(cachename, RSI_CACHE_NAME) != 0) {
		printerr(LL_ERR, "invalid cache name %s\n", cachename);
		return EXIT_FAILURE;
	}

	req_len = strlen(auth_req);

socket:
	/* Send auth request to lsvcgssd via a socket. */
	local_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (local_socket == -1) {
		printerr(LL_ERR, "cannot create socket: %d\n", -errno);
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, GSS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

connect:
	if (connect(local_socket, (struct sockaddr *)&addr,
		    sizeof(addr)) == -1) {
		rc = -errno;
		printerr(LL_ERR, "cannot connect to socket: %d\n", rc);
		if (debug || tried_daemon == 5)
			goto out;
		if (!tried_daemon) {
			rc = start_daemon(auth_req);
			if (rc) {
				rc = -1;
				goto out;
			}
			sleep(2);
		}
		tried_daemon++;
		goto connect;
	}

	if (debug)
		goto out;

	bytes_sent = write(local_socket, auth_req, req_len);
	if (bytes_sent < 0) {
		rc = -errno;
		printerr(LL_ERR, "write failed: %d\n", rc);
	} else if (bytes_sent != req_len) {
		printerr(LL_ERR, "partial write %zu vs. %zu\n",
		       bytes_sent, req_len);
		rc = -EMSGSIZE;
	}

out:
	close(local_socket);
	return rc < 0 ? EXIT_FAILURE : 0;
}
