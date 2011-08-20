#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <loafers.h>

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

	loafers_conn_t *conn;
	loafers_stream_t *stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_alloc(&conn)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_alloc: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_version(conn, SOCKS_VERSION_5)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_version: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	socks_method_e methods[] = { SOCKS_METHOD_NONE };
	if( loafers_errno(rc = loafers_set_methods(conn, 1, methods)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_methods: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_command(conn, SOCKS_CMD_CONNECT)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_command: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_set_hostname(conn, argv[3], htons(atoi(argv[4])))) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_set_hostname: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_stream_socket_alloc(&stream, sock)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_stream_socket_alloc: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_handshake(conn, stream)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_handshake: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_conn_free(&conn)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_conn_free: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}
	if( loafers_errno(rc = loafers_stream_free(&stream)) != LOAFERS_ERR_NOERR ) {
		fprintf(stderr, "loafers_stream_free: %s\n", loafers_strerror(rc));
		exit(EXIT_FAILURE);
	}

	char *args[] = { "cat", NULL };
	pid_t pid = fork();
	if( pid == -1 ) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if( pid == 0 ) {
		close(0);
		if( dup2(sock, 0) == -1 ) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(sock);
		execvp(args[0], args);
		perror("execvp");
		exit(EXIT_FAILURE);
	} else {
		close(1);
		if( dup2(sock, 1) == -1 ) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(sock);
		execvp(args[0], args);
		perror("execvp");
		exit(EXIT_FAILURE);
	}
}
