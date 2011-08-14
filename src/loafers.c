#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

#include "config.h"

#include "loafers.h"
#include "_loafers.h"

static void loafers_free( void *ptr ) {
	free(ptr);
	ptr = NULL;
}

loafers_err_e loafers_errno( loafers_rc_t err ) {
	return err.code;
}

loafers_err_socks_e loafers_socks_errno( loafers_rc_t err ) {
	return err.socks_errno;
}

int loafers_sys_errno( loafers_rc_t err ) {
	return err.sys_errno;
}

static loafers_rc_t loafers_rc( loafers_err_e err ) {
	loafers_rc_t ret;
	memset(&ret, 0, sizeof(loafers_rc_t));
	ret.code = err;
	return ret;
}

static loafers_rc_t loafers_rc_sys() {
	loafers_rc_t ret = loafers_rc(LOAFERS_ERR_ERRNO);
	ret.sys_errno = errno;
	return ret;
}

loafers_rc_t loafers_get_bind_addr( loafers_conn_t *conn, socks_atyp_e *atyp, socks_addr_u **addr ) {
	if( conn == NULL || atyp == NULL || addr == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}
	if( !conn->reply_avail ) {
		errno = EINVAL;
		return loafers_rc_sys();
	}
	*atyp = conn->reply.atyp;
	*addr = &conn->reply.bnd_addr;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_get_bind_port( loafers_conn_t *conn, in_port_t *port ) {
	if( conn == NULL || port == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}
	if( !conn->reply_avail ) {
		errno = EINVAL;
		return loafers_rc_sys();
	}
	*port = conn->reply.bnd_port;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err ) {
	loafers_rc_t ret = loafers_rc(err);
	ret.socks_errno = socks_err;
	return ret;
}

static const char *socks_strerror( loafers_err_socks_e err ) {
	static const char * const errors[] = {
		[SOCKS_ERR_NOERR] = "No error",
		[SOCKS_ERR_GENFAIL] = "General SOCKS server failure",
		[SOCKS_ERR_NOTALLOWED] = "Connection not allowed by ruleset",
		[SOCKS_ERR_NETUNREACH] = "Network unreachable",
		[SOCKS_ERR_HOSTUNREACH] = "Host unreachable",
		[SOCKS_ERR_CONNREFUSED] = "Connection refused",
		[SOCKS_ERR_TTLEXPIRED] = "TTL expired",
		[SOCKS_ERR_CMDNOTSUP] = "Command not supported",
		[SOCKS_ERR_AFNOTSUP] = "Address type not supported",
	};
	static const size_t noerrors = sizeof(errors) / sizeof(char *);
	if( err >= noerrors ) return "Unknown error";
	return errors[err];
}

const char *loafers_strerror( loafers_rc_t err ) {
	switch( err.code ) {
		case LOAFERS_ERR_ERRNO:
			return strerror(err.sys_errno);
		case LOAFERS_ERR_SOCKS:
			return socks_strerror(err.socks_errno);
		default: {
			static const char * const errors[] = {
				[LOAFERS_ERR_NOERR] = "No error",
				[LOAFERS_ERR_BADPACKET] = "Bad packet",
				[LOAFERS_ERR_EOF] = "Premature EOF",
				[LOAFERS_ERR_NEED_READ] = "Handshake needs read",
				[LOAFERS_ERR_NEED_WRITE] = "Handshake needs write",
				[LOAFERS_ERR_ERRNO] = "System error",
				[LOAFERS_ERR_SOCKS] = "Protocol error",
				[LOAFERS_ERR_BADSTATE] = "Invalid state machine"
			};
			static const size_t noerrors = sizeof(errors) / sizeof(char *);
			loafers_err_e errnum = loafers_errno(err);
			if( errnum >= noerrors ) return "Unknown error";
			return errors[errnum];
		}
	}
}

static loafers_rc_t loafers_free_addr_u( socks_atyp_e atyp, socks_addr_u addr ) {
	switch( atyp ) {
		case SOCKS_ATYP_UNINIT:
			break;
		case SOCKS_ATYP_IPV6:
			if( addr.ip6 != NULL ) loafers_free(addr.ip6);
			break;
		case SOCKS_ATYP_IPV4:
			if( addr.ip4 != NULL ) loafers_free(addr.ip4);
			break;
		case SOCKS_ATYP_HOSTNAME:
			if( addr.hostname != NULL ) loafers_free(addr.hostname);
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_conn_alloc( loafers_conn_t **conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	*conn = malloc(sizeof(loafers_conn_t));
	if( *conn == NULL ) return loafers_rc_sys();
	bzero(*conn, sizeof(loafers_conn_t));
	(*conn)->state = LOAFERS_CONN_UNPREPARED;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_conn_free( loafers_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}
	if( conn->ver.methods != NULL ) loafers_free(conn->ver.methods);
	if( conn->buf != NULL ) loafers_free(conn->buf);
	if( conn->data != NULL ) loafers_free(conn->data);
	loafers_rc_t rc = loafers_free_addr_u(conn->req.atyp, conn->req.dst_addr);
	loafers_rc_t rc2 = loafers_free_addr_u(conn->reply.atyp, conn->reply.bnd_addr);
	loafers_free(conn);
	if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	if( loafers_errno(rc2) != LOAFERS_ERR_NOERR ) return rc2;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static void loafers_set_prepared( loafers_conn_t *conn ) {
	if( conn->ver.ver != SOCKS_VERSION_UNINIT &&
			conn->req.ver != SOCKS_VERSION_UNINIT &&
			conn->ver.nmethods != 0 &&
			conn->req.cmd != SOCKS_CMD_UNINIT &&
			conn->req.atyp != SOCKS_ATYP_UNINIT )
		conn->state = LOAFERS_CONN_VERSION_PREPARE;
}

loafers_rc_t loafers_set_version( loafers_conn_t *conn, socks_version_e version ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	conn->ver.ver = version;
	conn->req.ver = version;

	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_methods( loafers_conn_t *conn, uint8_t nmethods, const socks_method_e methods[static nmethods] ) {
	if( conn == NULL || methods == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	if( conn->ver.methods != NULL ) loafers_free(conn->ver.methods);
	conn->ver.methods = calloc(sizeof(socks_method_e), nmethods);
	if( conn->ver.methods == NULL ) return loafers_rc_sys();
	memcpy(conn->ver.methods, methods, nmethods * sizeof(socks_method_e));
	conn->ver.nmethods = nmethods;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_command( loafers_conn_t *conn, socks_cmd_e cmd ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	conn->req.cmd = cmd;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_set_atyp( loafers_conn_t *conn, socks_atyp_e atyp ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	conn->req.atyp = atyp;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_hostname( loafers_conn_t *conn, const char *hostname, in_port_t port ) {
	if( conn == NULL || hostname == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	socks_request_t *req = &conn->req;
	loafers_rc_t rc = loafers_set_atyp(conn, SOCKS_ATYP_HOSTNAME);
	if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	req->dst_port = port;
	if( req->dst_addr.hostname != NULL ) loafers_free(req->dst_addr.hostname);
	req->addrsiz = (strlen(hostname) + 1) * sizeof(char);
	req->dst_addr.hostname = malloc(req->addrsiz);
	if( req->dst_addr.hostname == NULL ) return loafers_rc_sys();
	memcpy(req->dst_addr.hostname, hostname, req->addrsiz);
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_sockaddr( loafers_conn_t *conn, const struct sockaddr *address ) {
	if( conn == NULL || address == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	socks_request_t *req = &conn->req;
	loafers_rc_t rc;
	switch( address->sa_family ) {
		case AF_INET:
			if( loafers_errno(rc = loafers_set_atyp(conn, SOCKS_ATYP_IPV4)) != LOAFERS_ERR_NOERR ) return rc;
			struct sockaddr_in *addr = (struct sockaddr_in *) address;
			req->dst_port = addr->sin_port;
			if( req->dst_addr.ip4 != NULL ) loafers_free(req->dst_addr.ip4);
			req->addrsiz = sizeof(struct in_addr);
			req->dst_addr.ip4 = malloc(req->addrsiz);
			if( req->dst_addr.ip4 == NULL ) return loafers_rc_sys();
			memcpy(req->dst_addr.ip4, &addr->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			if( loafers_errno(rc = loafers_set_atyp(conn, SOCKS_ATYP_IPV6)) != LOAFERS_ERR_NOERR ) return rc;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
			req->dst_port = addr6->sin6_port;
			if( req->dst_addr.ip6 != NULL ) loafers_free(req->dst_addr.ip6);
			req->addrsiz = sizeof(struct in6_addr);
			req->dst_addr.ip6 = malloc(req->addrsiz);
			if( req->dst_addr.ip6 == NULL ) return loafers_rc_sys();
			memcpy(req->dst_addr.ip6, &addr6->sin6_addr, sizeof(struct in6_addr));
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count ) {
	size_t bufsiz = count * sizeof(uint8_t);
	uint8_t *buf = realloc(conn->buf, bufsiz);
	if( buf == NULL ) return loafers_rc_sys();
	conn->buf = buf;
	conn->bufptr = buf;
	conn->bufremain = bufsiz;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_write( int fd, loafers_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	uint8_t *bufptr = conn->bufptr;
	size_t bufremain = conn->bufremain;

	loafers_rc_t rc = loafers_rc(LOAFERS_ERR_NOERR);
	do {
		ssize_t ret = write(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) {
				continue;
			} else if( errno == EAGAIN || errno == EWOULDBLOCK ) {
				rc = loafers_rc(LOAFERS_ERR_NEED_WRITE);
			} else {
				rc = loafers_rc_sys();
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

static loafers_rc_t loafers_read( int fd, loafers_conn_t *conn ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	uint8_t *bufptr = conn->bufptr;
	size_t bufremain = conn->bufremain;

	loafers_rc_t rc = loafers_rc(LOAFERS_ERR_NOERR);
	do {
		ssize_t ret = read(fd, bufptr, bufremain);
		if( ret == -1 ) {
			if( errno == EINTR ) {
				continue;
			} else if( errno == EAGAIN || errno == EWOULDBLOCK ) {
				rc = loafers_rc(LOAFERS_ERR_NEED_READ);
			} else {
				rc = loafers_rc_sys();
			}
			break;
		} else if( ret == 0 ) {
			rc = loafers_rc(LOAFERS_ERR_EOF);
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	conn->bufremain = bufremain;
	conn->bufptr = bufptr;
	return rc;
}

static loafers_rc_t loafers_conn_version_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	socks_version_t *ver = &conn->ver;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, ver->nmethods + (2 * sizeof(uint8_t)))) != LOAFERS_ERR_NOERR ) return rc;
	uint8_t *buf = conn->buf;
	buf[0] = ver->ver;
	buf[1] = ver->nmethods;
	for( uint8_t i = 0; i < ver->nmethods; i++ )
		buf[i + 2] = ver->methods[i];
	conn->state = LOAFERS_CONN_VERSION_SENDING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_version_sending( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_write(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_METHODSEL_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_methodsel_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, 2 * sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_METHODSEL_READING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_methodsel_reading( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	if( conn->buf[0] != conn->ver.ver ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc(LOAFERS_ERR_BADPACKET);
	}
	conn->state = LOAFERS_CONN_REQUEST_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_request_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	socks_request_t *req = &conn->req;
	size_t addrsiz = req->addrsiz;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, addrsiz + (4 * sizeof(uint8_t)) + sizeof(uint16_t))) != LOAFERS_ERR_NOERR ) return rc;
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
			return loafers_rc_sys();
	}
	bufptr += addrsiz;
	memcpy(bufptr, &req->dst_port, sizeof(uint16_t));
	conn->state = LOAFERS_CONN_REQUEST_SENDING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_request_sending( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_write(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_REPLY_HEADER_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	conn->reply_avail = false;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, 4 * sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( (conn->data = realloc(conn->data, sizeof(uint8_t))) == NULL ) return loafers_rc_sys();
	conn->state = LOAFERS_CONN_REPLY_HEADER_READING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_reading( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	conn->reply.ver = conn->buf[0];
	conn->reply.rep = conn->buf[1];
	assert(conn->buf[2] == 0x00);
	conn->reply.atyp = conn->buf[3];
	if( conn->reply.ver != conn->req.ver ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc(LOAFERS_ERR_BADPACKET);
	}
	if( conn->reply.rep != SOCKS_ERR_NOERR ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc_socks(LOAFERS_ERR_SOCKS, conn->reply.rep);
	}
	uint8_t *addrsiz = (uint8_t *) conn->data;
	switch( conn->reply.atyp ) {
		case SOCKS_ATYP_IPV6:
			*addrsiz = 16;
			conn->state = LOAFERS_CONN_REPLY_PREPARE;
			break;
		case SOCKS_ATYP_IPV4:
			*addrsiz = 4;
			conn->state = LOAFERS_CONN_REPLY_PREPARE;
			break;
		case SOCKS_ATYP_HOSTNAME:
			conn->state = LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE;
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_reading( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	*((uint8_t *) conn->data) = conn->buf[0];
	conn->state = LOAFERS_CONN_REPLY_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_prepare( loafers_conn_t *conn, int sockfd ) {
	(void) sockfd;
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, buflen + sizeof(uint16_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( conn->reply.atyp == SOCKS_ATYP_HOSTNAME ) buflen++;
	void *bnd_addr;
	if( (bnd_addr = malloc(buflen)) == NULL ) return loafers_rc_sys();
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
			loafers_free(bnd_addr);
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	conn->state = LOAFERS_CONN_REPLY_READING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_reading( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
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
			return loafers_rc_sys();
	}
	memcpy(s1, conn->buf, buflen);
	conn->reply.bnd_port = ntohs(*((in_port_t *) &conn->buf[buflen]));
	conn->reply_avail = true;
	if( conn->req.cmd == SOCKS_CMD_BIND && conn->bindwait == false ) {
		conn->bindwait = true;
		conn->state = LOAFERS_CONN_REPLY_HEADER_PREPARE;
		return loafers_rc(LOAFERS_ERR_NOERR_BINDWAIT);
	} else {
		conn->state = LOAFERS_CONN_CONNECTED;
		return loafers_rc(LOAFERS_ERR_NOERR);
	}
}

loafers_rc_t loafers_handshake( loafers_conn_t *conn, int sockfd ) {
	if( conn == NULL ) {
		assert(false);
		errno = EINVAL;
		return loafers_rc_sys();
	}

	while( conn->state != LOAFERS_CONN_CONNECTED ) {
		if( conn->state >= loafers_nostates ) return loafers_rc(LOAFERS_ERR_BADSTATE);
		loafers_rc_t rc = loafers_state_handlers[conn->state](conn, sockfd);
		if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}
