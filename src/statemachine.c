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

#include "_common.h"
#include "_statemachine.h"

static const loafers_state_handler loafers_state_handlers[] = {
	[LOAFERS_CONN_VERSION_PREPARE] = loafers_conn_version_prepare,
	[LOAFERS_CONN_VERSION_SENDING] = loafers_conn_version_sending,
	[LOAFERS_CONN_METHODSEL_PREPARE] = loafers_conn_methodsel_prepare,
	[LOAFERS_CONN_METHODSEL_READING] = loafers_conn_methodsel_reading,
	[LOAFERS_CONN_REQUEST_PREPARE] = loafers_conn_request_prepare,
	[LOAFERS_CONN_REQUEST_SENDING] = loafers_conn_request_sending,
	[LOAFERS_CONN_REPLY_HEADER_PREPARE] = loafers_conn_reply_header_prepare,
	[LOAFERS_CONN_REPLY_HEADER_READING] = loafers_conn_reply_header_reading,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE] = loafers_conn_reply_header_hostlen_prepare,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING] = loafers_conn_reply_header_hostlen_reading,
	[LOAFERS_CONN_REPLY_PREPARE] = loafers_conn_reply_prepare,
	[LOAFERS_CONN_REPLY_READING] = loafers_conn_reply_reading
};
const size_t loafers_nostates = sizeof(loafers_state_handlers) / sizeof(loafers_state_handler);

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
			free(bnd_addr);
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
