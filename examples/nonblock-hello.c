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

#include <shoes.h>

int main( int argc, char *argv[] ) {
	if( argc != 5 ) {
		fprintf(stderr, "Usage: %s shostname sport hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

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

	struct shoes_conn_t *conn;
	shoes_rc_e rc;
	if( (rc = shoes_conn_alloc(&conn)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_alloc: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}
	if( (rc = shoes_set_version(conn, SOCKS_VERSION_5)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_set_version: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( (rc = shoes_set_methods(conn, methods, 1)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_set_methods: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}
	if( (rc = shoes_set_command(conn, SOCKS_CMD_CONNECT)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_set_command: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}
	if( (rc = shoes_set_hostname(conn, argv[3], htons(atoi(argv[4])))) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_set_hostname: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}

	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_SET(sock, &rfds);
	FD_SET(sock, &wfds);
	while( true ) {
		if( (rc = shoes_handshake(conn, sock)) != SHOES_ERR_NOERR ) {
			if( rc != SHOES_ERR_ERRNO && rc != SHOES_ERR_NEED_WRITE && rc != SHOES_ERR_NEED_READ ) {
				fprintf(stderr, "shoes_handshake: %s\n", shoes_strerror(rc));
				shoes_conn_free(conn);
				exit(EXIT_FAILURE);
			}
		}
		if( shoes_is_connected(conn) ) {
			break;
		} else {
			if( rc == SHOES_ERR_NEED_WRITE ) {
				if( select(sock + 1, NULL, &wfds, NULL, NULL) == -1 ) {
					perror("select");
					exit(EXIT_FAILURE);
				}
			} else if( rc == SHOES_ERR_NEED_READ ) {
				if( select(sock + 1, &rfds, NULL, NULL, NULL) == -1 ) {
					perror("select");
					exit(EXIT_FAILURE);
				}
			} else {
				fprintf(stderr, "Handshake needs neither read nor write\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	if( (rc = shoes_conn_free(conn)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_conn_free: %s\n", shoes_strerror(rc));
		exit(EXIT_FAILURE);
	}

	FILE *s = fdopen(sock, "a+");
	if( s == NULL ) {
		perror("fdopen");
		exit(EXIT_FAILURE);
	}
	fprintf(s, "Hello World!\n");
	fclose(s);
	return EXIT_SUCCESS;
}
