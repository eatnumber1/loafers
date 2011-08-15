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
	[LOAFERS_CONN_BIND_REPLY_HEADER_PREPARE] = loafers_conn_bind_reply_header_prepare,
	[LOAFERS_CONN_BIND_REPLY_HEADER_READING] = loafers_conn_bind_reply_header_reading,
	[LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_PREPARE] = loafers_conn_bind_reply_header_hostlen_prepare,
	[LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_READING] = loafers_conn_bind_reply_header_hostlen_reading,
	[LOAFERS_CONN_BIND_REPLY_PREPARE] = loafers_conn_bind_reply_prepare,
	[LOAFERS_CONN_BIND_REPLY_READING] = loafers_conn_bind_reply_reading,
	[LOAFERS_CONN_REPLY_HEADER_PREPARE] = loafers_conn_reply_header_prepare,
	[LOAFERS_CONN_REPLY_HEADER_READING] = loafers_conn_reply_header_reading,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE] = loafers_conn_reply_header_hostlen_prepare,
	[LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING] = loafers_conn_reply_header_hostlen_reading,
	[LOAFERS_CONN_REPLY_PREPARE] = loafers_conn_reply_prepare,
	[LOAFERS_CONN_REPLY_READING] = loafers_conn_reply_reading
};
static const size_t loafers_nostates = sizeof(loafers_state_handlers) / sizeof(loafers_state_handler);

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
	conn->state = conn->req.cmd == SOCKS_CMD_BIND ? LOAFERS_CONN_BIND_REPLY_HEADER_PREPARE : LOAFERS_CONN_REPLY_HEADER_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_generic_reply_header_prepare( loafers_conn_t *conn, int sockfd, bool *avail_flag, socks_reply_t **reply, loafers_conn_e next_state ) {
	(void) sockfd;
	loafers_rc_t rc;
	*avail_flag = false;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, 4 * sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( (conn->data = realloc(conn->data, sizeof(uint8_t))) == NULL ) return loafers_rc_sys();
	if( (*reply = malloc(sizeof(socks_reply_t))) == NULL ) return loafers_rc_sys();
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_prepare(conn, sockfd, &conn->reply_avail, &conn->reply, LOAFERS_CONN_REPLY_HEADER_READING);
}

static loafers_rc_t loafers_conn_bind_reply_header_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_prepare(conn, sockfd, &conn->bnd_reply_avail, &conn->bnd_reply, LOAFERS_CONN_BIND_REPLY_HEADER_READING);
}

// next_states must contain the equivalent of { LOAFERS_CONN_REPLY_PREPARE, LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE }
static loafers_rc_t loafers_conn_generic_reply_header_reading( loafers_conn_t *conn, int sockfd, socks_reply_t *reply, const loafers_conn_e next_states[const static 2] ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	reply->ver = conn->buf[0];
	reply->rep = conn->buf[1];
	assert(conn->buf[2] == 0x00);
	reply->atyp = conn->buf[3];
	if( reply->ver != conn->req.ver ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc(LOAFERS_ERR_BADPACKET);
	}
	if( reply->rep != SOCKS_ERR_NOERR ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc_socks(LOAFERS_ERR_SOCKS, reply->rep);
	}
	uint8_t *addrsiz = (uint8_t *) conn->data;
	switch( reply->atyp ) {
		case SOCKS_ATYP_IPV6:
			*addrsiz = 16;
			conn->state = next_states[0];
			break;
		case SOCKS_ATYP_IPV4:
			*addrsiz = 4;
			conn->state = next_states[0];
			break;
		case SOCKS_ATYP_HOSTNAME:
			conn->state = next_states[1];
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_reading( loafers_conn_t *conn, int sockfd ) {
	static const loafers_conn_e states[2] = {
		LOAFERS_CONN_REPLY_PREPARE,
		LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE
	};
	return loafers_conn_generic_reply_header_reading(conn, sockfd, conn->reply, states);
}

static loafers_rc_t loafers_conn_bind_reply_header_reading( loafers_conn_t *conn, int sockfd ) {
	static const loafers_conn_e states[2] = {
		LOAFERS_CONN_BIND_REPLY_PREPARE,
		LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_PREPARE
	};
	return loafers_conn_generic_reply_header_reading(conn, sockfd, conn->bnd_reply, states);
}

static loafers_rc_t loafers_conn_generic_reply_header_hostlen_prepare( loafers_conn_t *conn, int sockfd, loafers_conn_e next_state ) {
	(void) sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_hostlen_prepare(conn, sockfd, LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING);
}

static loafers_rc_t loafers_conn_bind_reply_header_hostlen_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_hostlen_prepare(conn, sockfd, LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_READING);
}

static loafers_rc_t loafers_conn_generic_reply_header_hostlen_reading( loafers_conn_t *conn, int sockfd, loafers_conn_e next_state ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	*((uint8_t *) conn->data) = conn->buf[0];
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_reading( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_hostlen_reading(conn, sockfd, LOAFERS_CONN_REPLY_PREPARE);
}

static loafers_rc_t loafers_conn_bind_reply_header_hostlen_reading( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_header_hostlen_reading(conn, sockfd, LOAFERS_CONN_BIND_REPLY_PREPARE);
}

static loafers_rc_t loafers_conn_generic_reply_prepare( loafers_conn_t *conn, int sockfd, socks_reply_t *reply, loafers_conn_e next_state ) {
	(void) sockfd;
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, buflen + sizeof(uint16_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( reply->atyp == SOCKS_ATYP_HOSTNAME ) buflen++;
	void *bnd_addr;
	if( (bnd_addr = malloc(buflen)) == NULL ) return loafers_rc_sys();
	switch( reply->atyp ) {
		case SOCKS_ATYP_IPV6:
			reply->bnd_addr.ip6 = (struct in6_addr *) bnd_addr;
			break;
		case SOCKS_ATYP_IPV4:
			reply->bnd_addr.ip4 = (struct in_addr *) bnd_addr;
			break;
		case SOCKS_ATYP_HOSTNAME:
			reply->bnd_addr.hostname = (char *) bnd_addr;
			reply->bnd_addr.hostname[buflen - 1] = '\0';
			break;
		default:
			free(bnd_addr);
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_prepare(conn, sockfd, conn->reply, LOAFERS_CONN_REPLY_READING);
}

static loafers_rc_t loafers_conn_bind_reply_prepare( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_prepare(conn, sockfd, conn->bnd_reply, LOAFERS_CONN_BIND_REPLY_READING);
}

static loafers_rc_t loafers_conn_generic_reply_reading( loafers_conn_t *conn, int sockfd, bool *avail_flag, socks_reply_t *reply, loafers_conn_e next_state ) {
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_read(sockfd, conn)) != LOAFERS_ERR_NOERR ) return rc;
	void *s1;
	switch( reply->atyp ) {
		case SOCKS_ATYP_IPV6:
			s1 = reply->bnd_addr.ip6;
			break;
		case SOCKS_ATYP_IPV4:
			s1 = reply->bnd_addr.ip4;
			break;
		case SOCKS_ATYP_HOSTNAME:
			s1 = reply->bnd_addr.hostname;
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	memcpy(s1, conn->buf, buflen);
	reply->bnd_port = ntohs(*((in_port_t *) &conn->buf[buflen]));
	*avail_flag = true;
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_reading( loafers_conn_t *conn, int sockfd ) {
	return loafers_conn_generic_reply_reading(conn, sockfd, &conn->reply_avail, conn->reply, LOAFERS_CONN_CONNECTED);
}

static loafers_rc_t loafers_conn_bind_reply_reading( loafers_conn_t *conn, int sockfd ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_generic_reply_reading(conn, sockfd, &conn->bnd_reply_avail, conn->bnd_reply, LOAFERS_CONN_REPLY_HEADER_PREPARE)) != LOAFERS_ERR_NOERR ) return rc;
	return loafers_rc(LOAFERS_ERR_NOERR_BINDWAIT);
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
