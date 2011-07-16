// TODO: Optimize the includes.

#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <inttypes.h>
#import <arpa/inet.h>
#import <strings.h>
#import <unistd.h>

#import <stdint.h>

#import <sys/types.h>
#import <sys/socket.h>
#import <assert.h>
#import <stdbool.h>
#import <limits.h>
#import <errno.h>
#import <netdb.h>

#import <libpack.h>

#import "shoes.h"

typedef enum {
	SOCKS_ATYP_IPV4 = 0x01,
	SOCKS_ATYP_HOSTNAME = 0x03,
	SOCKS_ATYP_IPV6 = 0x04
} socks_atyp_e;

typedef enum {
	SOCKS_REPLY_SUCCESS = 0x00,
	SOCKS_REPLY_GENFAIL = 0x01
} socks_reply_e;

typedef struct {
	socks_version_e ver;
	uint8_t nmethods;
	socks_method_e *methods;
} socks_version_t;

typedef struct {
	socks_version_e ver;
	socks_method_e method;
} socks_methodsel_t;

typedef struct {
	struct in_addr *ip4;
	struct in6_addr *ip6;
	char *hostname;
} socks_addr_u;

typedef struct {
	socks_version_e ver;
	socks_cmd_e cmd;
	socks_atyp_e atyp;
	in_port_t dst_port;
	socks_addr_u dst_addr;
} socks_request_t;

typedef struct {
	socks_version_e ver;
	socks_reply_e rep;
	socks_atyp_e atyp;
	in_port_t bnd_port;
	socks_addr_u bnd_addr;
} socks_reply_t;

typedef enum {
	SHOES_ERR_NOERR
} shoes_rc_e;

struct shoes_conn_t {
	socks_version_t ver;
	socks_request_t req;
};

struct shoes_conn_t *shoes_alloc() {
	struct shoes_conn_t *conn = malloc(sizeof(struct shoes_conn_t));
	if( conn == NULL ) return NULL;
	return conn;
}

static void shoes_free_addr_u( socks_addr_u addr, socks_atyp_e atyp ) {
	switch( atyp ) {
		case SOCKS_ATYP_IPV6:
			free(addr.ip6);
			break;
		case SOCKS_ATYP_IPV4:
			free(addr.ip4);
			break;
		case SOCKS_ATYP_HOSTNAME:
			free(addr.hostname);
			break;
		default:
			assert(false);
	}
}

void shoes_free( struct shoes_conn_t *conn ) {
	free(conn->ver.methods);
	shoes_free_addr_u(conn->req.dst_addr, conn->req.atyp);
	free(conn);
}

bool shoes_set_version( struct shoes_conn_t *conn, socks_version_e version ) {
	conn->ver.ver = version;
	conn->req.ver = version;
	return true;
}

bool shoes_set_methods( struct shoes_conn_t *conn, const socks_method_e *methods, uint8_t nmethods ) {
	conn->ver.methods = calloc(sizeof(socks_method_e), nmethods);
	if( conn->ver.methods == NULL ) return false;
	memcpy(conn->ver.methods, methods, nmethods * sizeof(socks_method_e));
	conn->ver.nmethods = nmethods;
	return true;
}

bool shoes_set_command( struct shoes_conn_t *conn, socks_cmd_e cmd ) {
	conn->req.cmd = cmd;
	return true;
}

static bool shoes_set_atyp( struct shoes_conn_t *conn, socks_atyp_e atyp ) {
	conn->req.atyp = atyp;
	return true;
}

bool shoes_set_hostname( struct shoes_conn_t *conn, const char *hostname, in_port_t port ) {
	if( !shoes_set_atyp(conn, SOCKS_ATYP_HOSTNAME) ) return false;
	conn->req.dst_port = port;
	conn->req.dst_addr.hostname = strdup(hostname);
	return conn->req.dst_addr.hostname != NULL;
}

bool shoes_set_sockaddr( struct shoes_conn_t *conn, const struct sockaddr *address ) {
	socks_request_t *req = &conn->req;
	switch( address->sa_family ) {
		case AF_INET:
			if( !shoes_set_atyp(conn, SOCKS_ATYP_IPV4) ) return false;
			struct sockaddr_in *addr = (struct sockaddr_in *) address;
			req->dst_port = addr->sin_port;
			req->dst_addr.ip4 = malloc(sizeof(struct in_addr));
			if( req->dst_addr.ip4 == NULL ) return false;
			memcpy(req->dst_addr.ip4, &addr->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			if( !shoes_set_atyp(conn, SOCKS_ATYP_IPV6) ) return false;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
			req->dst_port = addr6->sin6_port;
			req->dst_addr.ip6 = malloc(sizeof(struct in6_addr));
			if( req->dst_addr.ip6 == NULL ) return false;
			memcpy(req->dst_addr.ip6, &addr6->sin6_addr, sizeof(struct in_addr));
			break;
		default:
			// TODO: Error message
			return false;
	}
	return true;
}

static shoes_rc_e shoes_pack_version( PackStream *stream, const socks_version_t *ver ) {
	pack(stream, "u8> u8>[u8>]", ver->ver, ver->methods, ver->nmethods);
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_addr( PackStream *stream, const socks_atyp_e atyp, socks_addr_u *addr ) {
	size_t count;
	switch( atyp ) {
		case SOCKS_ATYP_IPV6:
			addr->ip6 = malloc(sizeof(struct in6_addr));
			unpack(stream, "u8>[16]", &addr->ip6->s6_addr);
			count = 16;
			break;
		case SOCKS_ATYP_IPV4:
			addr->ip4 = malloc(sizeof(struct in_addr));
			unpack(stream, "u32>", &addr->ip4->s_addr);
			count = 4;
			break;
		case SOCKS_ATYP_HOSTNAME:
			unpack(stream, "u8>", &count);
			addr->hostname = calloc(sizeof(char), count + 1);
			unpack(stream, "u8>[]", addr->hostname, count);
			addr->hostname[count++] = '\0';
			break;
		default:
			assert(false);
	}
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_reply( PackStream *stream, socks_reply_t **rep ) {
	socks_reply_t *reply = malloc(sizeof(socks_reply_t));
	uint8_t rsv;
	unpack(stream, "u8>4", &reply->ver, &reply->rep, &rsv, &reply->atyp);
	assert(reply->ver == SOCKS_VERSION_5);
	assert(reply->rep == SOCKS_REPLY_SUCCESS);
	shoes_unpack_addr(stream, reply->atyp, &reply->bnd_addr);
	unpack(stream, "u16>", &reply->bnd_port);
	*rep = reply;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_methodsel( PackStream *stream, socks_methodsel_t **methodsel ) {
	socks_methodsel_t *m = malloc(sizeof(socks_methodsel_t));
	unpack(stream, "u8>2", &m->ver, &m->method);
	assert(m->ver == SOCKS_VERSION_5);
	assert(m->method == SOCKS_METHOD_NONE);
	*methodsel = m;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_pack_addr( PackStream *stream, const socks_atyp_e atyp, const socks_addr_u *addr ) {
	size_t addr_len = 2;
	switch( atyp ) {
		case SOCKS_ATYP_IPV6:
			pack(stream, "u8>[16]", addr->ip6->s6_addr);
			break;
		case SOCKS_ATYP_IPV4:
			pack(stream, "u32>", addr->ip4->s_addr);
			break;
		case SOCKS_ATYP_HOSTNAME:
			addr_len = strlen(addr->hostname);
			pack(stream, "u8> u8>[]", addr_len, addr->hostname, addr_len);
			break;
		default:
			assert(false);
	}
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_pack_request( PackStream *stream, const socks_request_t *request ) {
	pack(stream, "u8>4", request->ver, request->cmd, 0x00, request->atyp);
	shoes_pack_addr(stream, request->atyp, &request->dst_addr);
	pack(stream, "u16>", request->dst_port);
	return SHOES_ERR_NOERR;
}

bool shoes_handshake_f( struct shoes_conn_t *conn, FILE *sock ) {
	PackStream *stream = packstream_file_new(sock);

	shoes_pack_version(stream, &conn->ver);
	fflush(sock);

	socks_methodsel_t *methodsel;
	shoes_unpack_methodsel(stream, &methodsel);
	free(methodsel);

	shoes_pack_request(stream, &conn->req);
	fflush(sock);
	
	socks_reply_t *reply;
	shoes_unpack_reply(stream, &reply);
	shoes_free_addr_u(reply->bnd_addr, reply->atyp);
	free(reply);

	packstream_file_free(stream);
	
	return true;
}

bool shoes_handshake( struct shoes_conn_t *conn, int socket ) {
	int sockfd = dup(socket);
	FILE *sock = fdopen(sockfd, "a+");
	shoes_handshake_f(conn, sock);
	fclose(sock);
	return true;
}
