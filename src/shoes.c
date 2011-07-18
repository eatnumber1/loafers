// TODO: Optimize the includes.

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <strings.h>

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
#include <unistd.h>

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
	size_t addrsiz;
} socks_request_t;

typedef struct {
	socks_version_e ver;
	shoes_rc_e rep;
	socks_atyp_e atyp;
	in_port_t bnd_port;
	socks_addr_u bnd_addr;
} socks_reply_t;

typedef enum {
	SHOES_CONN_VERSION_PREPARE,
	SHOES_CONN_VERSION_SENDING,
	SHOES_CONN_METHODSEL_PREPARE,
	SHOES_CONN_METHODSEL_READING,
	SHOES_CONN_REQUEST_PREPARE,
	SHOES_CONN_REQUEST_SENDING,
	SHOES_CONN_REPLY_HEADER_PREPARE,
	SHOES_CONN_REPLY_HEADER_READING,
	SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE,
	SHOES_CONN_REPLY_HEADER_HOSTLEN_READING,
	SHOES_CONN_REPLY_PREPARE,
	SHOES_CONN_REPLY_READING,
	SHOES_CONN_CONNECTED,
	SHOES_CONN_INVALID
} shoes_connstate_e;

struct shoes_conn_t {
	socks_version_t ver;
	socks_request_t req;
	size_t addrsiz;
};

struct shoes_connstate_t {
	shoes_connstate_e state;
	uint8_t *buf, *bufptr;
	size_t bufremain;
	// For passing information between states.
	void *data;
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
		[SHOES_ERR_EOF] = "Premature EOF",
	};
	static const size_t noerrors = sizeof(errors) / sizeof(char *);
	if( err >= noerrors ) return "Unknown error";
	return errors[err];
}

shoes_rc_e shoes_conn_alloc( struct shoes_conn_t **conn ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	*conn = malloc(sizeof(struct shoes_conn_t));
	if( *conn == NULL ) return SHOES_ERR_ERRNO;
	bzero(*conn, sizeof(struct shoes_conn_t));
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_free_addr_u( socks_atyp_e atyp, socks_addr_u addr ) {
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
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_conn_free( struct shoes_conn_t *conn ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}
	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	shoes_rc_e rc = shoes_free_addr_u(conn->req.atyp, conn->req.dst_addr);
	int err = 0;
	if( rc != SHOES_ERR_NOERR ) err = errno;
	free(conn);
	errno = err;
	return rc;
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

	socks_request_t *req = &conn->req;
	shoes_rc_e rc = shoes_set_atyp(conn, SOCKS_ATYP_HOSTNAME);
	if( rc != SHOES_ERR_NOERR ) return rc;
	req->dst_port = port;
	if( req->dst_addr.hostname != NULL ) free(req->dst_addr.hostname);
	req->addrsiz = (strlen(hostname) + 1) * sizeof(char);
	req->dst_addr.hostname = malloc(req->addrsiz);
	if( req->dst_addr.hostname == NULL ) return SHOES_ERR_ERRNO;
	memcpy(req->dst_addr.hostname, hostname, req->addrsiz);
	return SHOES_ERR_NOERR;
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
			req->addrsiz = sizeof(struct in_addr);
			req->dst_addr.ip4 = malloc(req->addrsiz);
			if( req->dst_addr.ip4 == NULL ) return SHOES_ERR_ERRNO;
			memcpy(req->dst_addr.ip4, &addr->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			if( !shoes_set_atyp(conn, SOCKS_ATYP_IPV6) ) return false;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
			req->dst_port = addr6->sin6_port;
			if( req->dst_addr.ip6 != NULL ) free(req->dst_addr.ip6);
			req->addrsiz = sizeof(struct in6_addr);
			req->dst_addr.ip6 = malloc(req->addrsiz);
			if( req->dst_addr.ip6 == NULL ) return SHOES_ERR_ERRNO;
			memcpy(req->dst_addr.ip6, &addr6->sin6_addr, sizeof(struct in_addr));
			break;
		default:
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

bool shoes_is_connected( struct shoes_connstate_t *connstate ) {
	assert(connstate != NULL);
	return connstate->state == SHOES_CONN_CONNECTED;
}

bool shoes_needs_write( struct shoes_connstate_t *connstate ) {
	assert(connstate != NULL);
	return connstate->state == SHOES_CONN_VERSION_PREPARE ||
		connstate->state == SHOES_CONN_VERSION_SENDING ||
		connstate->state == SHOES_CONN_REQUEST_PREPARE ||
		connstate->state == SHOES_CONN_REQUEST_SENDING;
}

bool shoes_needs_read( struct shoes_connstate_t *connstate ) {
	assert(connstate != NULL);
	return connstate->state == SHOES_CONN_METHODSEL_PREPARE ||
		connstate->state == SHOES_CONN_METHODSEL_READING ||
		connstate->state == SHOES_CONN_REPLY_HEADER_PREPARE ||
		connstate->state == SHOES_CONN_REPLY_HEADER_READING ||
		connstate->state == SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE ||
		connstate->state == SHOES_CONN_REPLY_HEADER_HOSTLEN_READING ||
		connstate->state == SHOES_CONN_REPLY_PREPARE ||
		connstate->state == SHOES_CONN_REPLY_READING;
}

shoes_rc_e shoes_connstate_alloc( struct shoes_connstate_t **connstate ) {
	if( connstate == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}
	*connstate = malloc(sizeof(struct shoes_connstate_t));
	if( *connstate == NULL ) return SHOES_ERR_ERRNO;
	bzero(*connstate, sizeof(struct shoes_connstate_t));
	(*connstate)->state = SHOES_CONN_VERSION_PREPARE;
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_connstate_free( struct shoes_connstate_t *connstate ) {
	if( connstate == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}
	if( connstate->buf != NULL ) free(connstate->buf);
	if( connstate->data != NULL ) free(connstate->data);
	free(connstate);
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_connbuf_alloc( struct shoes_connstate_t *connstate, size_t count ) {
	size_t bufsiz = count * sizeof(uint8_t);
	uint8_t *buf = realloc(connstate->buf, bufsiz);
	if( buf == NULL ) return SHOES_ERR_NOERR;
	connstate->buf = buf;
	connstate->bufptr = buf;
	connstate->bufremain = bufsiz;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_write( int fd, struct shoes_connstate_t *connstate ) {
	if( connstate == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	uint8_t *bufptr = connstate->bufptr;
	size_t bufremain = connstate->bufremain;

	shoes_rc_e rc = SHOES_ERR_NOERR;
	do {
		ssize_t ret = write(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) continue;
			rc = SHOES_ERR_ERRNO;
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	connstate->bufremain = bufremain;
	connstate->bufptr = bufptr;
	return rc;
}

static shoes_rc_e shoes_read( int fd, struct shoes_connstate_t *connstate ) {
	if( connstate == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	uint8_t *bufptr = connstate->bufptr;
	size_t bufremain = connstate->bufremain;

	shoes_rc_e rc = SHOES_ERR_NOERR;
	do {
		ssize_t ret = read(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) continue;
			rc = SHOES_ERR_ERRNO;
			break;
		} else if( ret == 0 ) {
			rc = SHOES_ERR_EOF;
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	connstate->bufremain = bufremain;
	connstate->bufptr = bufptr;
	return rc;
}

shoes_rc_e shoes_handshake( struct shoes_conn_t *conn, struct shoes_connstate_t *state, int sockfd ) {
	if( conn == NULL ) {
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	struct shoes_connstate_t cs;
	struct shoes_connstate_t *connstate;
	if( state == NULL ) {
		bzero(&cs, sizeof(struct shoes_connstate_t));
		cs.state = SHOES_CONN_VERSION_PREPARE;
		connstate = &cs;
	} else {
		connstate = state;
	}
	shoes_rc_e rc;
	while( connstate->state != SHOES_CONN_CONNECTED ) {
		switch( connstate->state ) {
			case SHOES_CONN_VERSION_PREPARE: {
				socks_version_t *ver = &conn->ver;
				if( (rc = shoes_connbuf_alloc(connstate, ver->nmethods + (2 * sizeof(uint8_t)))) != SHOES_ERR_NOERR ) return rc;
				uint8_t *buf = connstate->buf;
				buf[0] = ver->ver;
				buf[1] = ver->nmethods;
				for( int i = 0; i < ver->nmethods; i++ )
					buf[i + 2] = ver->methods[i];
				connstate->state = SHOES_CONN_VERSION_SENDING;
			}
			case SHOES_CONN_VERSION_SENDING: {
				if( (rc = shoes_write(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_METHODSEL_PREPARE;
			}
			case SHOES_CONN_METHODSEL_PREPARE: {
				if( (rc = shoes_connbuf_alloc(connstate, 2 * sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_METHODSEL_READING;
			}
			case SHOES_CONN_METHODSEL_READING: {
				if( (rc = shoes_read(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				if( connstate->buf[0] != conn->ver.ver ) {
					connstate->state = SHOES_CONN_INVALID;
					return SHOES_ERR_BADPACKET;
				}
				connstate->state = SHOES_CONN_REQUEST_PREPARE;
			}
			case SHOES_CONN_REQUEST_PREPARE: {
				socks_request_t *req = &conn->req;
				size_t addrsiz = req->addrsiz;
				if( (rc = shoes_connbuf_alloc(connstate, addrsiz + (4 * sizeof(uint8_t)) + sizeof(uint16_t))) != SHOES_ERR_NOERR ) return rc;
				uint8_t *buf = connstate->buf;
				buf[0] = req->ver;
				buf[1] = req->cmd;
				buf[2] = 0x00;
				buf[3] = req->atyp;
				uint8_t *bufptr = buf + 4;
				switch( req->atyp ) {
					case SOCKS_ATYP_IPV6:
						memcpy(bufptr, req->dst_addr.ip6, addrsiz);
						break;
					case SOCKS_ATYP_IPV4:
						memcpy(bufptr, req->dst_addr.ip4, addrsiz);
						break;
					case SOCKS_ATYP_HOSTNAME: {
						*(bufptr++) = --addrsiz;
						memcpy(bufptr, req->dst_addr.hostname, addrsiz);
						break;
					}
					default:
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				bufptr += addrsiz;
				memcpy(bufptr, &req->dst_port, sizeof(uint16_t));
				connstate->state = SHOES_CONN_REQUEST_SENDING;
			}
			case SHOES_CONN_REQUEST_SENDING: {
				if( (rc = shoes_write(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_REPLY_HEADER_PREPARE;
			}
			case SHOES_CONN_REPLY_HEADER_PREPARE: {
				if( (rc = shoes_connbuf_alloc(connstate, 4 * sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				if( (connstate->data = realloc(connstate->data, sizeof(uint8_t))) == NULL ) return SHOES_ERR_ERRNO;
				connstate->state = SHOES_CONN_REPLY_HEADER_READING;
			}
			case SHOES_CONN_REPLY_HEADER_READING: {
				if( (rc = shoes_read(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				if( connstate->buf[0] != conn->req.ver ) {
					connstate->state = SHOES_CONN_INVALID;
					return SHOES_ERR_BADPACKET;
				}
				if( connstate->buf[1] != SHOES_ERR_NOERR ) {
					connstate->state = SHOES_CONN_INVALID;
					return connstate->buf[1];
				}
				uint8_t *addrsiz = (uint8_t *) connstate->data;
				switch( connstate->buf[3] ) {
					case SOCKS_ATYP_IPV6:
						*addrsiz = 16;
						connstate->state = SHOES_CONN_REPLY_PREPARE;
						break;
					case SOCKS_ATYP_IPV4:
						*addrsiz = 4;
						connstate->state = SHOES_CONN_REPLY_PREPARE;
						break;
					case SOCKS_ATYP_HOSTNAME:
						connstate->state = SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE;
						break;
					default:
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				break;
			}
			case SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE: {
				if( (rc = shoes_connbuf_alloc(connstate, sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_REPLY_HEADER_HOSTLEN_READING;
			}
			case SHOES_CONN_REPLY_HEADER_HOSTLEN_READING: {
				if( (rc = shoes_read(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				*((uint8_t *) connstate->data) = connstate->buf[0];
				connstate->state = SHOES_CONN_REPLY_PREPARE;
			}
			case SHOES_CONN_REPLY_PREPARE: {
				if( (rc = shoes_connbuf_alloc(connstate, *((uint8_t *) connstate->data) + sizeof(uint16_t))) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_REPLY_READING;
			}
			case SHOES_CONN_REPLY_READING: {
				if( (rc = shoes_read(sockfd, connstate)) != SHOES_ERR_NOERR ) return rc;
				connstate->state = SHOES_CONN_CONNECTED;
				break;
			}
			case SHOES_CONN_INVALID:
			default: {
				errno = EINVAL;
				return SHOES_ERR_ERRNO;
			}
		}
	}
	return SHOES_ERR_NOERR;
}
