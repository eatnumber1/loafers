#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <talloc.h>

#include "config.h"

#include "loafers.h"

#include "_common.h"
#include "_statemachine.h"

static const loafers_state_handler loafers_state_handlers[] = {
	[LOAFERS_CONN_VERSION_PREPARE] = loafers_conn_version_prepare,
	[LOAFERS_CONN_VERSION_SENDING] = loafers_conn_version_sending,
	[LOAFERS_CONN_VERSION_FLUSHING] = loafers_conn_version_flushing,
	[LOAFERS_CONN_METHODSEL_PREPARE] = loafers_conn_methodsel_prepare,
	[LOAFERS_CONN_METHODSEL_READING] = loafers_conn_methodsel_reading,
	[LOAFERS_CONN_REQUEST_PREPARE] = loafers_conn_request_prepare,
	[LOAFERS_CONN_REQUEST_SENDING] = loafers_conn_request_sending,
	[LOAFERS_CONN_REQUEST_FLUSHING] = loafers_conn_request_flushing,
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

static loafers_rc_t loafers_conn_write( loafers_stream_t *stream, loafers_conn_t *conn ) {
	loafers_rc_t rc = loafers_stream_write(stream, conn->bufptr, conn->bufremain);
	conn->bufptr += conn->bufremain;
	conn->bufremain = 0;
	return rc;
}

static loafers_rc_t loafers_conn_read( loafers_stream_t *stream, loafers_conn_t *conn ) {
	size_t count;
	loafers_rc_t rc = loafers_stream_read(stream, conn->bufptr, conn->bufremain, &count);
	conn->bufptr += count;
	conn->bufremain -= count;
	return rc;
}

static loafers_rc_t loafers_conn_version_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	(void) stream;
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

static loafers_rc_t loafers_conn_version_sending( loafers_conn_t *conn, loafers_stream_t *stream ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_write(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_VERSION_FLUSHING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_version_flushing( loafers_conn_t *conn, loafers_stream_t *stream ) {
	(void) conn;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_stream_flush(stream)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_METHODSEL_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);;
}

static loafers_rc_t loafers_conn_methodsel_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	(void) stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, 2 * sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_METHODSEL_READING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_methodsel_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_read(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
	if( conn->buf[0] != conn->ver.ver ) {
		conn->state = LOAFERS_CONN_INVALID;
		return loafers_rc(LOAFERS_ERR_BADPACKET);
	}
	conn->state = LOAFERS_CONN_REQUEST_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_request_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	(void) stream;
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

static loafers_rc_t loafers_conn_request_sending( loafers_conn_t *conn, loafers_stream_t *stream ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_write(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = LOAFERS_CONN_REQUEST_FLUSHING;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_request_flushing( loafers_conn_t *conn, loafers_stream_t *stream ) {
	(void) conn;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_stream_flush(stream)) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = conn->req.cmd == SOCKS_CMD_BIND ? LOAFERS_CONN_BIND_REPLY_HEADER_PREPARE : LOAFERS_CONN_REPLY_HEADER_PREPARE;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_generic_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream, bool *avail_flag, socks_reply_t **r, loafers_conn_e next_state ) {
	(void) stream;
	loafers_rc_t rc;
	*avail_flag = false;
	socks_reply_t *reply = *r;
	void *data = conn->data;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, 4 * sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( (data = talloc_realloc(conn, data, uint8_t, 1)) == NULL ) return loafers_rc_sys();
	loafers_talloc_name(data);
	if( (reply = talloc_realloc(conn, reply, socks_reply_t, 1)) == NULL ) return loafers_rc_sys();
	loafers_talloc_name(reply);
	memset(reply, 0, sizeof(socks_reply_t));
	conn->state = next_state;
	conn->data = data;
	*r = reply;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_prepare(conn, stream, &conn->reply_avail, &conn->reply, LOAFERS_CONN_REPLY_HEADER_READING);
}

static loafers_rc_t loafers_conn_bind_reply_header_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_prepare(conn, stream, &conn->bnd_reply_avail, &conn->bnd_reply, LOAFERS_CONN_BIND_REPLY_HEADER_READING);
}

// next_states must contain the equivalent of { LOAFERS_CONN_REPLY_PREPARE, LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE }
static loafers_rc_t loafers_conn_generic_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream, socks_reply_t *reply, const loafers_conn_e next_states[const static 2] ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_read(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
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

static loafers_rc_t loafers_conn_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	static const loafers_conn_e states[2] = {
		LOAFERS_CONN_REPLY_PREPARE,
		LOAFERS_CONN_REPLY_HEADER_HOSTLEN_PREPARE
	};
	return loafers_conn_generic_reply_header_reading(conn, stream, conn->reply, states);
}

static loafers_rc_t loafers_conn_bind_reply_header_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	static const loafers_conn_e states[2] = {
		LOAFERS_CONN_BIND_REPLY_PREPARE,
		LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_PREPARE
	};
	return loafers_conn_generic_reply_header_reading(conn, stream, conn->bnd_reply, states);
}

static loafers_rc_t loafers_conn_generic_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream, loafers_conn_e next_state ) {
	(void) stream;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, sizeof(uint8_t))) != LOAFERS_ERR_NOERR ) return rc;
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_hostlen_prepare(conn, stream, LOAFERS_CONN_REPLY_HEADER_HOSTLEN_READING);
}

static loafers_rc_t loafers_conn_bind_reply_header_hostlen_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_hostlen_prepare(conn, stream, LOAFERS_CONN_BIND_REPLY_HEADER_HOSTLEN_READING);
}

static loafers_rc_t loafers_conn_generic_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream, loafers_conn_e next_state ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_read(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
	*((uint8_t *) conn->data) = conn->buf[0];
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_hostlen_reading(conn, stream, LOAFERS_CONN_REPLY_PREPARE);
}

static loafers_rc_t loafers_conn_bind_reply_header_hostlen_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_header_hostlen_reading(conn, stream, LOAFERS_CONN_BIND_REPLY_PREPARE);
}

static loafers_rc_t loafers_conn_generic_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream, socks_reply_t *reply, loafers_conn_e next_state ) {
	(void) stream;
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, buflen + sizeof(uint16_t))) != LOAFERS_ERR_NOERR ) return rc;
	if( reply->atyp == SOCKS_ATYP_HOSTNAME ) buflen++;
	void *bnd_addr;
	if( (bnd_addr = talloc_size(conn, buflen)) == NULL ) return loafers_rc_sys();
	switch( reply->atyp ) {
		case SOCKS_ATYP_IPV6:
			talloc_set_type(bnd_addr, struct in6_addr);
			reply->bnd_addr.ip6 = (struct in6_addr *) bnd_addr;
			break;
		case SOCKS_ATYP_IPV4:
			talloc_set_type(bnd_addr, struct in_addr);
			reply->bnd_addr.ip4 = (struct in_addr *) bnd_addr;
			break;
		case SOCKS_ATYP_HOSTNAME:
			talloc_set_type(bnd_addr, char);
			reply->bnd_addr.hostname = (char *) bnd_addr;
			reply->bnd_addr.hostname[buflen - 1] = '\0';
			break;
		default:
			assert(false);
			errno = EINVAL;
			return loafers_rc_sys();
	}
	loafers_talloc_name(bnd_addr);
	conn->state = next_state;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_conn_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_prepare(conn, stream, conn->reply, LOAFERS_CONN_REPLY_READING);
}

static loafers_rc_t loafers_conn_bind_reply_prepare( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_prepare(conn, stream, conn->bnd_reply, LOAFERS_CONN_BIND_REPLY_READING);
}

static loafers_rc_t loafers_conn_generic_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream, bool *avail_flag, socks_reply_t *reply, loafers_conn_e next_state ) {
	loafers_rc_t rc;
	uint8_t buflen = *((uint8_t *) conn->data);
	if( loafers_errno(rc = loafers_conn_read(stream, conn)) != LOAFERS_ERR_NOERR ) return rc;
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

static loafers_rc_t loafers_conn_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	return loafers_conn_generic_reply_reading(conn, stream, &conn->reply_avail, conn->reply, LOAFERS_CONN_CONNECTED);
}

static loafers_rc_t loafers_conn_bind_reply_reading( loafers_conn_t *conn, loafers_stream_t *stream ) {
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_generic_reply_reading(conn, stream, &conn->bnd_reply_avail, conn->bnd_reply, LOAFERS_CONN_REPLY_HEADER_PREPARE)) != LOAFERS_ERR_NOERR ) return rc;
	return loafers_rc(LOAFERS_ERR_NOERR_BINDWAIT);
}

loafers_rc_t loafers_handshake( loafers_conn_t *conn, loafers_stream_t *stream ) {
	assert(conn != NULL);

	while( conn->state != LOAFERS_CONN_CONNECTED ) {
		if( conn->state >= loafers_nostates ) return loafers_rc(LOAFERS_ERR_BADSTATE);
		loafers_rc_t rc = loafers_state_handlers[conn->state](conn, stream);
		if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_udpassociate( loafers_conn_t *conn, loafers_stream_t *stream, loafers_resolver_f r, loafers_stream_t **udpstream ) {
	assert(conn != NULL && stream != NULL && udpstream != NULL);

	if( conn->req.cmd != SOCKS_CMD_UDP_ASSOCIATE ) {
		errno = EINVAL;
		return loafers_rc_sys();
	}
	loafers_rc_t rc;
	loafers_resolver_f resolver = r == NULL ? loafers_getaddrinfo_resolver : r;
	while( conn->udp.state != LOAFERS_UDP_ASSOCIATED ) {
		switch( conn->udp.state ) {
			case LOAFERS_UDP_HANDSHAKE:
				if( loafers_errno(rc = loafers_handshake(conn, stream)) != LOAFERS_ERR_NOERR ) return rc;
				conn->udp.state = LOAFERS_UDP_ADDRESS;
			case LOAFERS_UDP_ADDRESS: {
				void *ctx = talloc_new(conn);
				if( ctx == NULL ) return loafers_rc_sys();
				char *hostname;
				if( loafers_errno(rc = loafers_get_relay_addr(conn, &hostname)) != LOAFERS_ERR_NOERR ) {
					(void) talloc_free(ctx);
					return rc;
				}
				char *h = talloc_strdup(ctx, hostname);
				free(hostname);
				if( h == NULL ) {
					(void) talloc_free(ctx);
					return loafers_rc_sys();
				}
				hostname = h;
				in_port_t port;
				if( loafers_errno(rc = loafers_get_relay_port(conn, &port)) != LOAFERS_ERR_NOERR ) {
					(void) talloc_free(ctx);
					return rc;
				}
				char *servname = talloc_asprintf(ctx, "%" PRIu16, port);
				if( servname == NULL ) {
					(void) talloc_free(ctx);
					return loafers_rc_sys();
				}
				struct addrinfo **addr = talloc_ptrtype(ctx, addr);
				if( addr == NULL ) {
					(void) talloc_free(ctx);
					return loafers_rc_sys();
				}
				conn->udp.hostname = hostname;
				conn->udp.servname = servname;
				conn->udp.address = addr;
				conn->udp.state = LOAFERS_UDP_RESOLVE;
			}
			case LOAFERS_UDP_RESOLVE:
				if( loafers_errno(rc = resolver(conn->udp.hostname, conn->udp.servname, conn->udp.address)) != LOAFERS_ERR_NOERR ) return rc;
				talloc_set_destructor(conn->udp.address, loafers_resolve_addrinfo_free);
				conn->udp.state = LOAFERS_UDP_CONNECT;
			case LOAFERS_UDP_CONNECT: {
				int sock;
				for( struct addrinfo *res = *conn->udp.address; res != NULL; res = res->ai_next ) {
					sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
					if( sock == -1 ) {
						rc = loafers_rc_sys();
						continue;
					}
					if( connect(sock, res->ai_addr, res->ai_addrlen) != 0 ) {
						close(sock);
						rc = loafers_rc_sys();
						continue;
					}
					rc = loafers_rc(LOAFERS_ERR_NOERR);
					break;
				}
				if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
				if( loafers_errno(rc = loafers_stream_socket_alloc(udpstream, sock)) != LOAFERS_ERR_NOERR ) {
					close(sock);
					return loafers_rc_sys();
				}
				conn->udp.state = LOAFERS_UDP_ASSOCIATED;
				break;
			}
			default:
				assert(false);
				errno = EINVAL;
				return loafers_rc_sys();
		}
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}
