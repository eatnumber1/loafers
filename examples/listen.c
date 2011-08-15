#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>

#include <loafers.h>

loafers_conn_t *make_conn( socks_cmd_e cmd, char *hostname, char *port ) {
	loafers_conn_t *conn;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_alloc(&conn)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_alloc: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_version(conn, SOCKS_VERSION_5)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_version: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( loafers_errno(rc = loafers_set_methods(conn, 1, methods)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_methods: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_command(conn, cmd)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_command: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_hostname(conn, hostname, htons(atoi(port)))) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_hostname: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	return conn;
}

static struct addrinfo *res;

int listen_connect( char *argv[] ) {
	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if( sock == -1 ) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	
	if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	loafers_conn_t *conn = make_conn(SOCKS_CMD_CONNECT, argv[3], argv[4]);
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_handshake(conn, sock)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_handshake: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_conn_free(&conn)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_conn_free: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}

	return sock;
}

int listen_bind( char *argv[], loafers_conn_t **connptr ) {
	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = res->ai_family;
	hints.ai_socktype = res->ai_socktype;
	hints.ai_protocol = res->ai_protocol;
	struct addrinfo *res2;
	int retcode = getaddrinfo(NULL, argv[5], &hints, &res2);
	if( retcode != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retcode));
		exit(EXIT_FAILURE);
	}

	int sock = socket(res2->ai_family, res2->ai_socktype, res2->ai_protocol);
	if( sock == -1 ) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if( bind(sock, res2->ai_addr, res2->ai_addrlen) == -1 ) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res2);
	
	if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	assert(connptr != NULL);
	*connptr = make_conn(SOCKS_CMD_BIND, argv[3], argv[5]);
	loafers_conn_t *conn = *connptr;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_handshake(conn, sock)) != LOAFERS_ERR_NOERR_BINDWAIT ) {
		fprintf(stderr, "loafers_handshake: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}

	return sock;
}

int main( int argc, char *argv[] ) {
	if( argc != 6 ) {
		fprintf(stderr, "Usage: %s shostname sport host port listen_port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	int retcode = getaddrinfo(argv[1], argv[2], &hints, &res);
	if( retcode != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retcode));
		exit(EXIT_FAILURE);
	}

	int sock = listen_connect(argv);

	loafers_conn_t *conn;
	loafers_rc_t rc;
	int bind_sock = listen_bind(argv, &conn);
	char *bind_addr;
	in_port_t bind_port;

	if( loafers_errno(rc = loafers_get_bind_addr(conn, &bind_addr)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_get_bind_addr: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_get_bind_port(conn, &bind_port)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_get_bind_port: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}

	FILE *s = fdopen(sock, "a+");
	if( s == NULL ) {
		perror("fdopen");
		exit(EXIT_FAILURE);
	}
	fprintf(s, "%s %" PRIu16 "\n", bind_addr, bind_port);
	fflush(s);
	free(bind_addr);

	if( loafers_errno(rc = loafers_handshake(conn, bind_sock)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_handshake: %s\n", loafers_strerror(rc));
		loafers_conn_free(&conn);
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_conn_free(&conn)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_conn_free: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}

	FILE *bs = fdopen(bind_sock, "a+");
	if( s == NULL ) {
		perror("fdopen");
		exit(EXIT_FAILURE);
	}
	do {
		int c;
		if( (c = fgetc(bs)) == EOF ) {
			if( ferror(bs) ) {
				perror("fgetc");
				exit(EXIT_FAILURE);
			}
		} else {
			printf("%c", (unsigned char) c);
		}
	} while( !feof(bs) );

	freeaddrinfo(res);
	fclose(bs);
	fclose(s);

	return EXIT_SUCCESS;
}
