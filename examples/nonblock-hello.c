#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

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

	int flags = fcntl(sock, F_GETFL);
	if( flags == -1 ) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}

	if( fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1 ) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}

	loafers_conn_t *conn;
	loafers_stream_t *stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_alloc(&conn)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_alloc");
	if( loafers_errno(rc = loafers_set_version(conn, SOCKS_VERSION_5)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_version");
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( loafers_errno(rc = loafers_set_methods(conn, 1, methods)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_methods");
	if( loafers_errno(rc = loafers_set_command(conn, SOCKS_CMD_CONNECT)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_command");
	if( loafers_errno(rc = loafers_set_hostname(conn, argv[3], htons(atoi(argv[4])))) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_hostname");
	if( loafers_errno(rc = loafers_stream_socket_alloc(&stream, sock)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_stream_socket_alloc");

	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_SET(sock, &rfds);
	FD_SET(sock, &wfds);
	loafers_err_e code;
	do {
		switch( code = loafers_errno(rc = loafers_handshake(conn, stream)) ) {
			case LOAFERS_ERR_NOERR:
				break;
			case LOAFERS_ERR_NEED_WRITE:
				if( select(sock + 1, NULL, &wfds, NULL, NULL) == -1 ) {
					perror("select");
					exit(EXIT_FAILURE);
				}
				break;
			case LOAFERS_ERR_NEED_READ:
				if( select(sock + 1, &rfds, NULL, NULL, NULL) == -1 ) {
					perror("select");
					exit(EXIT_FAILURE);
				}
				break;
			default:
				loafers_die(rc, "loafers_handshake");
		}
	} while( code != LOAFERS_ERR_NOERR );

	if( loafers_errno(rc = loafers_conn_free(&conn)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_conn_free");

	const char *hello = "Hello World!\n";
	const size_t hellolen = strlen(hello);
	do {
		loafers_err_e code;
		switch( code = loafers_errno(rc = loafers_write(stream, hello, hellolen)) ) {
			case LOAFERS_ERR_NOERR:
				break;
			case LOAFERS_ERR_NEED_WRITE:
				if( select(sock + 1, NULL, &wfds, NULL, NULL) == -1 ) {
					perror("select");
					exit(EXIT_FAILURE);
				}
				break;
			default:
				loafers_die(rc, "loafers_write");
		}
	} while( code != LOAFERS_ERR_NOERR );
	if( loafers_errno(rc = loafers_stream_close(&stream)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_stream_free");
	return EXIT_SUCCESS;
}
