#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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

	struct shoes_conn_t *conn;
	shoes_rc_e rc;
	if( (rc = shoes_conn_alloc(&conn)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_alloc: %s\n", shoes_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( (rc = shoes_set_version(conn, SOCKS_VERSION_5)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_set_version: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
	}
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( (rc = shoes_set_methods(conn, 1, methods)) != SHOES_ERR_NOERR ) {
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
	if( (rc = shoes_handshake(conn, sock)) != SHOES_ERR_NOERR ) {
		fprintf(stderr, "shoes_handshake: %s\n", shoes_strerror(rc));
		shoes_conn_free(conn);
		exit(EXIT_FAILURE);
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
