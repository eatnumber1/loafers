// TODO: Optimize the includes.

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <netdb.h>

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <libpack.h>

#include "shoes.h"

#include "config.h"

typedef enum {
	SOCKS_ATYP_UNINIT = 0x00,
	SOCKS_ATYP_IPV4 = 0x01,
	SOCKS_ATYP_HOSTNAME = 0x03,
	SOCKS_ATYP_IPV6 = 0x04
} socks_atyp_e;

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
	shoes_rc_e rep;
	socks_atyp_e atyp;
	in_port_t bnd_port;
	socks_addr_u bnd_addr;
} socks_reply_t;

struct shoes_conn_t {
	socks_version_t ver;
	socks_request_t req;
};

const char *shoes_strerror( shoes_rc_e err ) {
	if( err == SHOES_ERR_ERRNO ) {
		return strerror(errno);
	}
	static const char *errors[] = {
		[SHOES_ERR_NOERR] = "No error",
		[SHOES_ERR_GENFAIL] = "General SOCKS server failure",
		[SHOES_ERR_NOTALLOWED] = "Connection not allowed by ruleset",
		[SHOES_ERR_NETUNREACH] = "Network unreachable",
		[SHOES_ERR_HOSTUNREACH] = "Host unreachable",
		[SHOES_ERR_CONNREFUSED] = "Connection refused",
		[SHOES_ERR_TTLEXPIRED] = "TTL expired",
		[SHOES_ERR_CMDNOTSUP] = "Command not supported",
		[SHOES_ERR_AFNOTSUP] = "Address type not supported",
		[SHOES_ERR_BADPACKET] = "Bad packet",
		[SHOES_ERR_NOTIMPL] = "Not implemented"
	};
	static const size_t noerrors = sizeof(errors) / sizeof(char *);
	if( err >= noerrors ) return "Unknown error";
	return errors[err];
}

shoes_rc_e shoes_alloc( struct shoes_conn_t **conn ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	*conn = malloc(sizeof(struct shoes_conn_t));
	if( *conn == NULL ) return SHOES_ERR_ERRNO;
	bzero(*conn, sizeof(struct shoes_conn_t));
	return SHOES_ERR_NOERR;
}

static void shoes_free_addr_u( socks_addr_u addr, socks_atyp_e atyp ) {
	switch( atyp ) {
		case SOCKS_ATYP_UNINIT:
			break;
		case SOCKS_ATYP_IPV6:
			if( addr.ip6 != NULL ) free(addr.ip6);
			break;
		case SOCKS_ATYP_IPV4:
			if( addr.ip4 != NULL ) free(addr.ip4);
			break;
		case SOCKS_ATYP_HOSTNAME:
			if( addr.hostname != NULL ) free(addr.hostname);
			break;
		default:
			assert(false);
	}
}

void shoes_free( struct shoes_conn_t *conn ) {
	if( conn == NULL ) return;
	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	shoes_free_addr_u(conn->req.dst_addr, conn->req.atyp);
	free(conn);
}

shoes_rc_e shoes_set_version( struct shoes_conn_t *conn, socks_version_e version ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->ver.ver = version;
	conn->req.ver = version;

	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_methods( struct shoes_conn_t *conn, const socks_method_e *methods, uint8_t nmethods ) {
	if( conn == NULL || methods == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	conn->ver.methods = calloc(sizeof(socks_method_e), nmethods);
	if( conn->ver.methods == NULL ) return SHOES_ERR_ERRNO;
	memcpy(conn->ver.methods, methods, nmethods * sizeof(socks_method_e));
	conn->ver.nmethods = nmethods;
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_command( struct shoes_conn_t *conn, socks_cmd_e cmd ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->req.cmd = cmd;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_set_atyp( struct shoes_conn_t *conn, socks_atyp_e atyp ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->req.atyp = atyp;
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_hostname( struct shoes_conn_t *conn, const char *hostname, in_port_t port ) {
	if( conn == NULL || hostname == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	shoes_rc_e rc = shoes_set_atyp(conn, SOCKS_ATYP_HOSTNAME);
	if( rc != SHOES_ERR_NOERR ) return rc;
	conn->req.dst_port = port;
	if( conn->req.dst_addr.hostname != NULL ) free(conn->req.dst_addr.hostname);
	conn->req.dst_addr.hostname = strdup(hostname);
	return conn->req.dst_addr.hostname == NULL ? SHOES_ERR_ERRNO : SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_sockaddr( struct shoes_conn_t *conn, const struct sockaddr *address ) {
	if( conn == NULL || address == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	socks_request_t *req = &conn->req;
	switch( address->sa_family ) {
		case AF_INET:
			if( !shoes_set_atyp(conn, SOCKS_ATYP_IPV4) ) return false;
			struct sockaddr_in *addr = (struct sockaddr_in *) address;
			req->dst_port = addr->sin_port;
			if( req->dst_addr.ip4 != NULL ) free(req->dst_addr.ip4);
			req->dst_addr.ip4 = malloc(sizeof(struct in_addr));
			if( req->dst_addr.ip4 == NULL ) return SHOES_ERR_ERRNO;
			memcpy(req->dst_addr.ip4, &addr->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			if( !shoes_set_atyp(conn, SOCKS_ATYP_IPV6) ) return false;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
			req->dst_port = addr6->sin6_port;
			if( req->dst_addr.ip6 != NULL ) free(req->dst_addr.ip6);
			req->dst_addr.ip6 = malloc(sizeof(struct in6_addr));
			if( req->dst_addr.ip6 == NULL ) return SHOES_ERR_ERRNO;
			memcpy(req->dst_addr.ip6, &addr6->sin6_addr, sizeof(struct in_addr));
			break;
		default:
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_pack_version( PackStream *stream, const socks_version_t *ver ) {
	if( stream == NULL || ver == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	return pack(stream, "u8> u8>[u8>]", ver->ver, ver->methods, ver->nmethods) == -1 ? SHOES_ERR_ERRNO : SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_addr( PackStream *stream, const socks_atyp_e atyp, socks_addr_u *addr ) {
	if( stream == NULL || addr == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	size_t count;
	switch( atyp ) {
		case SOCKS_ATYP_IPV6:
			if( addr->ip6 != NULL ) free(addr->ip6);
			addr->ip6 = malloc(sizeof(struct in6_addr));
			if( addr->ip6 == NULL ) return SHOES_ERR_ERRNO;
			if( unpack(stream, "u8>[16]", &addr->ip6->s6_addr) == -1 ) {
				free(addr->ip6);
				addr->ip6 = NULL;
				return SHOES_ERR_ERRNO;
			}
			count = 16;
			break;
		case SOCKS_ATYP_IPV4:
			if( addr->ip4 != NULL ) free(addr->ip4);
			addr->ip4 = malloc(sizeof(struct in_addr));
			if( addr->ip4 == NULL ) return SHOES_ERR_ERRNO;
			if( unpack(stream, "u32>", &addr->ip4->s_addr) == -1 ) {
				free(addr->ip4);
				addr->ip4 = NULL;
				return SHOES_ERR_ERRNO;
			}
			count = 4;
			break;
		case SOCKS_ATYP_HOSTNAME:
			unpack(stream, "u8>", &count);
			if( addr->hostname != NULL ) free(addr->hostname);
			addr->hostname = calloc(sizeof(char), count + 1);
			if( addr->hostname == NULL ) return SHOES_ERR_ERRNO;
			if( unpack(stream, "u8>[]", addr->hostname, count) == -1 ) {
				free(addr->hostname);
				addr->hostname = NULL;
				return SHOES_ERR_ERRNO;
			}
			addr->hostname[count] = '\0';
			break;
		default:
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_reply( PackStream *stream, socks_reply_t **rep ) {
	if( stream == NULL || rep == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	socks_reply_t *reply = malloc(sizeof(socks_reply_t));
	bzero(reply, sizeof(socks_reply_t));
	if( reply == NULL ) return SHOES_ERR_ERRNO;
	uint8_t rsv;
	if( unpack(stream, "u8>4", &reply->ver, &reply->rep, &rsv, &reply->atyp) == -1 ) {
		free(reply);
		return SHOES_ERR_ERRNO;
	}
	if( reply->ver != SOCKS_VERSION_5 ) {
		free(reply);
		return SHOES_ERR_BADPACKET;
	}
	if( reply->rep != SHOES_ERR_NOERR ) {
		shoes_rc_e ret = reply->rep;
		free(reply);
		return ret;
	}
	shoes_rc_e rc = shoes_unpack_addr(stream, reply->atyp, &reply->bnd_addr);
	if( rc != SHOES_ERR_NOERR ) {
		free(reply);
		return rc;
	}
	if( unpack(stream, "u16>", &reply->bnd_port) == -1 ) {
		free(reply);
		return SHOES_ERR_ERRNO;
	}
	*rep = reply;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_unpack_methodsel( PackStream *stream, socks_methodsel_t **methodsel ) {
	if( stream == NULL || methodsel == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	socks_methodsel_t *m = malloc(sizeof(socks_methodsel_t));
	if( m == NULL ) return SHOES_ERR_ERRNO;
	if( unpack(stream, "u8>2", &m->ver, &m->method) == -1 ) {
		free(m);
		return SHOES_ERR_ERRNO;
	}
	if( m->ver != SOCKS_VERSION_5 ) {
		free(m);
		return SHOES_ERR_BADPACKET;
	}
	// TODO: Implement more auth methods
	if( m->method != SOCKS_METHOD_NONE ) {
		free(m);
		return SHOES_ERR_NOTIMPL;
	}
	*methodsel = m;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_pack_addr( PackStream *stream, const socks_atyp_e atyp, const socks_addr_u *addr ) {
	if( stream == NULL || addr == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	size_t addr_len;
	switch( atyp ) {
		case SOCKS_ATYP_IPV6:
			if( pack(stream, "u8>[16]", addr->ip6->s6_addr) == -1 ) return SHOES_ERR_ERRNO;
			break;
		case SOCKS_ATYP_IPV4:
			if( pack(stream, "u32>", addr->ip4->s_addr) == -1 ) return SHOES_ERR_ERRNO;
			break;
		case SOCKS_ATYP_HOSTNAME:
			addr_len = strlen(addr->hostname);
			if( pack(stream, "u8> u8>[]", addr_len, addr->hostname, addr_len) == -1 ) return SHOES_ERR_ERRNO;
			break;
		default:
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_pack_request( PackStream *stream, const socks_request_t *request ) {
	if( stream == NULL || request == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	if( pack(stream, "u8>4", request->ver, request->cmd, 0x00, request->atyp) == -1 ) return SHOES_ERR_ERRNO;
	shoes_rc_e rc = shoes_pack_addr(stream, request->atyp, &request->dst_addr);
	if( rc != SHOES_ERR_NOERR ) return rc;
	return pack(stream, "u16>", request->dst_port) == -1 ? SHOES_ERR_ERRNO : SHOES_ERR_NOERR;
}

shoes_rc_e shoes_handshake_f( struct shoes_conn_t *conn, FILE *sock ) {
	if( conn == NULL || sock == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	PackStream *stream = packstream_file_new(sock);
	if( stream == NULL ) return SHOES_ERR_ERRNO;

	shoes_rc_e rc;
	if( (rc = shoes_pack_version(stream, &conn->ver)) != SHOES_ERR_NOERR ) {
		packstream_file_free(stream);
		return rc;
	}

	socks_methodsel_t *methodsel;
	if( (rc = shoes_unpack_methodsel(stream, &methodsel)) != SHOES_ERR_NOERR ) {
		packstream_file_free(stream);
		return rc;
	}
	free(methodsel);

	if( (rc = shoes_pack_request(stream, &conn->req)) != SHOES_ERR_NOERR ) {
		packstream_file_free(stream);
		return rc;
	}
	
	socks_reply_t *reply;
	if( (rc = shoes_unpack_reply(stream, &reply)) != SHOES_ERR_NOERR ) {
		packstream_file_free(stream);
		return rc;
	}
	shoes_free_addr_u(reply->bnd_addr, reply->atyp);
	free(reply);

	packstream_file_free(stream);
	
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_handshake( struct shoes_conn_t *conn, int socket ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	int sockfd = dup(socket);
	if( sockfd == -1 ) return SHOES_ERR_ERRNO;
	FILE *sock = fdopen(sockfd, "a+");
	if( sock == NULL ) {
		close(sockfd);
		return SHOES_ERR_ERRNO;
	}
	shoes_rc_e rc = shoes_handshake_f(conn, sock);
	fclose(sock);
	return rc;
}
