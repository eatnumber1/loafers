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
#include <unistd.h>
#include <assert.h>

#include <talloc.h>

#include <loafers.h>

__attribute__((noreturn))
static void loafers_die( loafers_rc_t rc, const char *s ) {
	fprintf(stderr, "%s: %s\n", s, loafers_strerror(rc));
	exit(EXIT_FAILURE);
}

static loafers_rc_t stream_destroy( void *data, loafers_stream_t *stream ) {
	(void) stream;
	free(data);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_retval_t stream_gen( void *data, const char *hostname, const char *servname, const struct addrinfo *hints, loafers_stream_t **stream ) {
	assert(data == NULL);
	loafers_retval_t retval = {
		.rc = loafers_rc(LOAFERS_ERR_NOERR),
		.data = data
	};
	int *sockptr = (int *) data;
	if( data == NULL ) {
		sockptr = malloc(sizeof(int));
		if( sockptr == NULL ) {
			retval.rc = loafers_rc_sys();
			return retval;
		}
	}
	retval.data = sockptr;
	struct addrinfo *r;
	int retcode = getaddrinfo(hostname, servname, hints, &r);
	if( retcode != 0 ) {
		retval.rc = loafers_rc(LOAFERS_ERR_GETADDRINFO);
		retval.rc.getaddrinfo_errno = retcode;
		free(sockptr);
		retval.data = NULL;
		return retval;
	}
	int sock;
	retval.rc = loafers_rc(LOAFERS_ERR_NOERR);
	for( struct addrinfo *res = r; res != NULL; res = res->ai_next ) {
		if( (sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1 ) {
			retval.rc = loafers_rc_sys();
			continue;
		}
		if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
			retval.rc = loafers_rc_sys();
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(r);
	if( loafers_errno(retval.rc) != LOAFERS_ERR_NOERR ) {
		free(sockptr);
		retval.data = NULL;
		return retval;
	}
	int flags = fcntl(sock, F_GETFL);
	if( flags == -1 ) {
		retval.rc = loafers_rc_sys();
		free(sockptr);
		retval.data = NULL;
		return retval;
	}
	if( fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1 ) {
		retval.rc = loafers_rc_sys();
		free(sockptr);
		retval.data = NULL;
		return retval;
	}
	if( loafers_errno(retval.rc = loafers_stream_socket_alloc(stream, sock)) != LOAFERS_ERR_NOERR ) {
		close(sock);
		free(sockptr);
		retval.data = NULL;
		return retval;
	}
	*sockptr = sock;
	retval.rc = loafers_rc(LOAFERS_ERR_NOERR);
	return retval;
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

	loafers_conn_t *conn;
	loafers_stream_t *stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_alloc(&conn)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_alloc");
	if( loafers_errno(rc = loafers_set_version(conn, SOCKS_VERSION_5)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_version");
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( loafers_errno(rc = loafers_set_methods(conn, 1, methods)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_methods");
	if( loafers_errno(rc = loafers_set_command(conn, SOCKS_CMD_CONNECT)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_command");
	if( loafers_errno(rc = loafers_set_hostname(conn, argv[3], htons(atoi(argv[4])))) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_hostname");
	if( loafers_errno(rc = loafers_set_proxy(conn, argv[1], argv[2], &hints)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_proxy");
	if( loafers_errno(rc = loafers_set_stream_generator(conn, stream_gen, stream_destroy)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_set_stream_generator");

	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	loafers_err_e code;
	int sock;
	int *sockptr = NULL;
	do {
		code = loafers_errno(rc = loafers_connect(conn, &stream));
		if( sockptr == NULL ) {
			switch( code = loafers_errno(rc) ) {
				case LOAFERS_ERR_NOERR:
				case LOAFERS_ERR_NEED_WRITE:
				case LOAFERS_ERR_NEED_READ: {
					loafers_retval_t retval;
					if( loafers_errno((retval = loafers_get_generator_data(stream)).rc) != LOAFERS_ERR_NOERR ) loafers_die(retval.rc, "loafers_get_generator_data");
					sockptr = (int *) retval.data;
					sock = *sockptr;
					FD_SET(sock, &rfds);
					FD_SET(sock, &wfds);
					break;
				}
				default:
					loafers_die(rc, "loafers_connect");
			}
		}
		switch( code = loafers_errno(rc) ) {
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
				loafers_die(rc, "loafers_connect");
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
	if( loafers_errno(rc = loafers_stream_close(&stream)) != LOAFERS_ERR_NOERR ) loafers_die(rc, "loafers_stream_close");
	return EXIT_SUCCESS;
}
