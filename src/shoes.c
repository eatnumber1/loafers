#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
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
	SHOES_CONN_UNPREPARED,
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
} shoes_conn_e;

struct shoes_conn_t {
	socks_version_t ver;
	socks_request_t req;
	socks_reply_t reply;
	size_t addrsiz;
	// Connection state information
	shoes_conn_e state;
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
		[SHOES_ERR_NEED_READ] = "Handshake needs read",
		[SHOES_ERR_NEED_WRITE] = "Handshake needs write"
	};
	static const size_t noerrors = sizeof(errors) / sizeof(char *);
	if( err >= noerrors ) return "Unknown error";
	return errors[err];
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
			assert(false);
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_conn_alloc( struct shoes_conn_t **conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	*conn = malloc(sizeof(struct shoes_conn_t));
	if( *conn == NULL ) return SHOES_ERR_ERRNO;
	bzero(*conn, sizeof(struct shoes_conn_t));
	(*conn)->state = SHOES_CONN_UNPREPARED;
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_conn_free( struct shoes_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}
	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	if( conn->buf != NULL ) free(conn->buf);
	if( conn->data != NULL ) free(conn->data);
	shoes_rc_e rc = shoes_free_addr_u(conn->req.atyp, conn->req.dst_addr);
	int err = 0;
	if( rc != SHOES_ERR_NOERR ) err = errno;
	rc = shoes_free_addr_u(conn->reply.atyp, conn->reply.bnd_addr);
	if( err == 0 && rc != SHOES_ERR_NOERR ) err = errno;
	free(conn);
	errno = err;
	return rc;
}

static void shoes_set_prepared( struct shoes_conn_t *conn ) {
	if( conn->ver.ver != SOCKS_VERSION_UNINIT &&
			conn->req.ver != SOCKS_VERSION_UNINIT &&
			conn->ver.nmethods != 0 &&
			conn->req.cmd != SOCKS_CMD_UNINIT &&
			conn->req.atyp != SOCKS_ATYP_UNINIT )
		conn->state = SHOES_CONN_VERSION_PREPARE;
}

shoes_rc_e shoes_set_version( struct shoes_conn_t *conn, socks_version_e version ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->ver.ver = version;
	conn->req.ver = version;

	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_methods( struct shoes_conn_t *conn, uint8_t nmethods, const socks_method_e methods[static nmethods] ) {
	if( conn == NULL || methods == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	conn->ver.methods = calloc(sizeof(socks_method_e), nmethods);
	if( conn->ver.methods == NULL ) return SHOES_ERR_ERRNO;
	memcpy(conn->ver.methods, methods, nmethods * sizeof(socks_method_e));
	conn->ver.nmethods = nmethods;
	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_command( struct shoes_conn_t *conn, socks_cmd_e cmd ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->req.cmd = cmd;
	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_set_atyp( struct shoes_conn_t *conn, socks_atyp_e atyp ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	conn->req.atyp = atyp;
	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_hostname( struct shoes_conn_t *conn, const char hostname[static], in_port_t port ) {
	if( conn == NULL || hostname == NULL ) {
		assert(false);
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
	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

shoes_rc_e shoes_set_sockaddr( struct shoes_conn_t *conn, const struct sockaddr *address ) {
	if( conn == NULL || address == NULL ) {
		assert(false);
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
			assert(false);
			errno = EINVAL;
			return SHOES_ERR_ERRNO;
	}
	shoes_set_prepared(conn);
	return SHOES_ERR_NOERR;
}

bool shoes_is_connected( struct shoes_conn_t *conn ) {
	assert(conn != NULL);
	return conn->state == SHOES_CONN_CONNECTED;
}

bool shoes_needs_write( struct shoes_conn_t *conn ) {
	assert(conn != NULL);
	return conn->state == SHOES_CONN_VERSION_PREPARE ||
		conn->state == SHOES_CONN_VERSION_SENDING ||
		conn->state == SHOES_CONN_REQUEST_PREPARE ||
		conn->state == SHOES_CONN_REQUEST_SENDING;
}

bool shoes_needs_read( struct shoes_conn_t *conn ) {
	assert(conn != NULL);
	return conn->state == SHOES_CONN_METHODSEL_PREPARE ||
		conn->state == SHOES_CONN_METHODSEL_READING ||
		conn->state == SHOES_CONN_REPLY_HEADER_PREPARE ||
		conn->state == SHOES_CONN_REPLY_HEADER_READING ||
		conn->state == SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE ||
		conn->state == SHOES_CONN_REPLY_HEADER_HOSTLEN_READING ||
		conn->state == SHOES_CONN_REPLY_PREPARE ||
		conn->state == SHOES_CONN_REPLY_READING;
}

static shoes_rc_e shoes_connbuf_alloc( struct shoes_conn_t *conn, size_t count ) {
	size_t bufsiz = count * sizeof(uint8_t);
	uint8_t *buf = realloc(conn->buf, bufsiz);
	if( buf == NULL ) return SHOES_ERR_ERRNO;
	conn->buf = buf;
	conn->bufptr = buf;
	conn->bufremain = bufsiz;
	return SHOES_ERR_NOERR;
}

static shoes_rc_e shoes_write( int fd, struct shoes_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	uint8_t *bufptr = conn->bufptr;
	size_t bufremain = conn->bufremain;

	shoes_rc_e rc = SHOES_ERR_NOERR;
	do {
		ssize_t ret = write(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) {
				continue;
			} else if( errno == EAGAIN || errno == EWOULDBLOCK ) {
				rc = SHOES_ERR_NEED_WRITE;
			} else {
				rc = SHOES_ERR_ERRNO;
			}
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	conn->bufremain = bufremain;
	conn->bufptr = bufptr;
	return rc;
}

static shoes_rc_e shoes_read( int fd, struct shoes_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	uint8_t *bufptr = conn->bufptr;
	size_t bufremain = conn->bufremain;

	shoes_rc_e rc = SHOES_ERR_NOERR;
	do {
		ssize_t ret = read(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) {
				continue;
			} else if( errno == EAGAIN || errno == EWOULDBLOCK ) {
				rc = SHOES_ERR_NEED_READ;
			} else {
				rc = SHOES_ERR_ERRNO;
			}
			break;
		} else if( ret == 0 ) {
			rc = SHOES_ERR_EOF;
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	conn->bufremain = bufremain;
	conn->bufptr = bufptr;
	return rc;
}

shoes_rc_e shoes_handshake( struct shoes_conn_t *conn, int sockfd ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return SHOES_ERR_ERRNO;
	}

	shoes_rc_e rc;
	while( conn->state != SHOES_CONN_CONNECTED ) {
		switch( conn->state ) {
			case SHOES_CONN_VERSION_PREPARE: {
				socks_version_t *ver = &conn->ver;
				if( (rc = shoes_connbuf_alloc(conn, ver->nmethods + (2 * sizeof(uint8_t)))) != SHOES_ERR_NOERR ) return rc;
				uint8_t *buf = conn->buf;
				buf[0] = ver->ver;
				buf[1] = ver->nmethods;
				for( int i = 0; i < ver->nmethods; i++ )
					buf[i + 2] = ver->methods[i];
				conn->state = SHOES_CONN_VERSION_SENDING;
			}
			case SHOES_CONN_VERSION_SENDING: {
				if( (rc = shoes_write(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				conn->state = SHOES_CONN_METHODSEL_PREPARE;
			}
			case SHOES_CONN_METHODSEL_PREPARE: {
				if( (rc = shoes_connbuf_alloc(conn, 2 * sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				conn->state = SHOES_CONN_METHODSEL_READING;
			}
			case SHOES_CONN_METHODSEL_READING: {
				if( (rc = shoes_read(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				if( conn->buf[0] != conn->ver.ver ) {
					conn->state = SHOES_CONN_INVALID;
					return SHOES_ERR_BADPACKET;
				}
				conn->state = SHOES_CONN_REQUEST_PREPARE;
			}
			case SHOES_CONN_REQUEST_PREPARE: {
				socks_request_t *req = &conn->req;
				size_t addrsiz = req->addrsiz;
				if( (rc = shoes_connbuf_alloc(conn, addrsiz + (4 * sizeof(uint8_t)) + sizeof(uint16_t))) != SHOES_ERR_NOERR ) return rc;
				uint8_t *buf = conn->buf;
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
						assert(false);
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				bufptr += addrsiz;
				memcpy(bufptr, &req->dst_port, sizeof(uint16_t));
				conn->state = SHOES_CONN_REQUEST_SENDING;
			}
			case SHOES_CONN_REQUEST_SENDING: {
				if( (rc = shoes_write(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				conn->state = SHOES_CONN_REPLY_HEADER_PREPARE;
			}
			case SHOES_CONN_REPLY_HEADER_PREPARE: {
				if( (rc = shoes_connbuf_alloc(conn, 4 * sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				if( (conn->data = realloc(conn->data, sizeof(uint8_t))) == NULL ) return SHOES_ERR_ERRNO;
				conn->state = SHOES_CONN_REPLY_HEADER_READING;
			}
			case SHOES_CONN_REPLY_HEADER_READING: {
				if( (rc = shoes_read(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				conn->reply.ver = conn->buf[0];
				conn->reply.rep = conn->buf[1];
				assert(conn->buf[2] == 0x00);
				conn->reply.atyp = conn->buf[3];
				if( conn->reply.ver != conn->req.ver ) {
					conn->state = SHOES_CONN_INVALID;
					return SHOES_ERR_BADPACKET;
				}
				if( conn->reply.rep != SHOES_ERR_NOERR ) {
					conn->state = SHOES_CONN_INVALID;
					return conn->reply.rep;
				}
				uint8_t *addrsiz = (uint8_t *) conn->data;
				switch( conn->reply.atyp ) {
					case SOCKS_ATYP_IPV6:
						*addrsiz = 16;
						conn->state = SHOES_CONN_REPLY_PREPARE;
						break;
					case SOCKS_ATYP_IPV4:
						*addrsiz = 4;
						conn->state = SHOES_CONN_REPLY_PREPARE;
						break;
					case SOCKS_ATYP_HOSTNAME:
						conn->state = SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE;
						break;
					default:
						assert(false);
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				break;
			}
			case SHOES_CONN_REPLY_HEADER_HOSTLEN_PREPARE: {
				if( (rc = shoes_connbuf_alloc(conn, sizeof(uint8_t))) != SHOES_ERR_NOERR ) return rc;
				conn->state = SHOES_CONN_REPLY_HEADER_HOSTLEN_READING;
			}
			case SHOES_CONN_REPLY_HEADER_HOSTLEN_READING: {
				if( (rc = shoes_read(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				*((uint8_t *) conn->data) = conn->buf[0];
				conn->state = SHOES_CONN_REPLY_PREPARE;
			}
			case SHOES_CONN_REPLY_PREPARE: {
				uint8_t buflen = *((uint8_t *) conn->data);
				if( (rc = shoes_connbuf_alloc(conn, buflen + sizeof(uint16_t))) != SHOES_ERR_NOERR ) return rc;
				if( conn->reply.atyp == SOCKS_ATYP_HOSTNAME ) buflen++;
				void *bnd_addr;
				if( (bnd_addr = malloc(buflen)) == NULL ) return SHOES_ERR_ERRNO;
				switch( conn->reply.atyp ) {
					case SOCKS_ATYP_IPV6:
						conn->reply.bnd_addr.ip6 = (struct in6_addr *) bnd_addr;
						break;
					case SOCKS_ATYP_IPV4:
						conn->reply.bnd_addr.ip4 = (struct in_addr *) bnd_addr;
						break;
					case SOCKS_ATYP_HOSTNAME:
						conn->reply.bnd_addr.hostname = (char *) bnd_addr;
						conn->reply.bnd_addr.hostname[buflen] = '\0';
						break;
					default:
						free(bnd_addr);
						assert(false);
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				conn->state = SHOES_CONN_REPLY_READING;
			}
			case SHOES_CONN_REPLY_READING: {
				uint8_t buflen = *((uint8_t *) conn->data);
				if( (rc = shoes_read(sockfd, conn)) != SHOES_ERR_NOERR ) return rc;
				void *s1;
				switch( conn->reply.atyp ) {
					case SOCKS_ATYP_IPV6:
						s1 = conn->reply.bnd_addr.ip6;
						break;
					case SOCKS_ATYP_IPV4:
						s1 = conn->reply.bnd_addr.ip4;
						break;
					case SOCKS_ATYP_HOSTNAME:
						s1 = conn->reply.bnd_addr.hostname;
						break;
					default:
						assert(false);
						errno = EINVAL;
						return SHOES_ERR_ERRNO;
				}
				memcpy(s1, conn->buf, buflen);
				conn->reply.bnd_port = ntohl(*((in_port_t *) &conn->buf[buflen]));
				conn->state = SHOES_CONN_CONNECTED;
				break;
			}
			case SHOES_CONN_UNPREPARED:
			case SHOES_CONN_INVALID:
			default: {
				assert(false);
				errno = EINVAL;
				return SHOES_ERR_ERRNO;
			}
		}
	}
	return SHOES_ERR_NOERR;
}
