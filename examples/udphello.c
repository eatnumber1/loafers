#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#include <talloc.h>

#include <loafers.h>

__attribute__((noreturn))
static void loafers_die( loafers_rc_t rc, const char *s ) {
	fprintf(stderr, "%s: %s\n", s, loafers_strerror(rc));
	exit(EXIT_FAILURE);
}

int main( int argc, char *argv[] ) {
	if( argc != 5 ) {
		fprintf(stderr, "Usage: %s shostname sport hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	talloc_set_log_stderr();
	talloc_enable_leak_report_full();

	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	struct addrinfo *res;
	int retcode = getaddrinfo(argv[1], argv[2], &hints, &res);
	if( retcode != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retcode));
		exit(EXIT_FAILURE);
	}

	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if( sock == -1 ) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	
	if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	loafers_conn_t *conn;
	loafers_stream_t *stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_alloc(&conn)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_alloc");
	if( loafers_errno(rc = loafers_set_version(conn, SOCKS_VERSION_5)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_version");
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( loafers_errno(rc = loafers_set_methods(conn, 1, methods)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_methods");
	if( loafers_errno(rc = loafers_set_command(conn, SOCKS_CMD_UDP_ASSOCIATE)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_command");
	if( loafers_errno(rc = loafers_set_hostname(conn, argv[3], htons(atoi(argv[4])))) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_hostname");
	if( loafers_errno(rc = loafers_connect(conn, &stream)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_udpassociate");
	if( loafers_errno(rc = loafers_conn_free(&conn)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_conn_free");

	const char *hello = "Hello World!\n";
	//if( loafers_errno(rc = loafers_write(stream, hello, strlen(hello) + 1)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_write");
	if( loafers_errno(rc = loafers_stream_close(&stream)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_stream_close");
	return EXIT_SUCCESS;
}
