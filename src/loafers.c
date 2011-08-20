#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"

#include "loafers.h"

#include "_common.h"
#include "_loafers.h"

loafers_err_e loafers_errno( loafers_rc_t err ) {
	return err.code;
}

loafers_err_socks_e loafers_socks_errno( loafers_rc_t err ) {
	return err.socks_errno;
}

int loafers_sys_errno( loafers_rc_t err ) {
	return err.sys_errno;
}

loafers_rc_t loafers_rc( loafers_err_e err ) {
	loafers_rc_t ret;
	memset(&ret, 0, sizeof(loafers_rc_t));
	ret.code = err;
	return ret;
}

loafers_rc_t loafers_rc_sys() {
	loafers_rc_t ret = loafers_rc(LOAFERS_ERR_ERRNO);
	ret.sys_errno = errno;
	return ret;
}

static loafers_rc_t loafers_get_generic_addr( loafers_conn_t *conn, char **addr, socks_reply_t *reply, bool *avail_flag ) {
	assert(conn != NULL && addr != NULL && reply != NULL && avail_flag != NULL);

	if( !*avail_flag ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	int ntop_af;
	void *ntop_src;
	socklen_t ntop_size;
	switch( reply->atyp ) {
		case SOCKS_ATYP_IPV4:
			ntop_size = INET_ADDRSTRLEN;
			ntop_af = AF_INET;
			ntop_src = reply->bnd_addr.ip4;
			break;
		case SOCKS_ATYP_IPV6:
			ntop_size = INET6_ADDRSTRLEN;
			ntop_af = AF_INET6;
			ntop_src = reply->bnd_addr.ip6;
			break;
		case SOCKS_ATYP_HOSTNAME:
			*addr = strdup(reply->bnd_addr.hostname);
			if( *addr == NULL ) return loafers_rc_sys();
			return loafers_rc(LOAFERS_ERR_NOERR);
		default:
			assert(false);
	}
	char *ret = malloc(ntop_size);
	if( ret == NULL ) return loafers_rc_sys();
	if( inet_ntop(ntop_af, ntop_src, ret, ntop_size) == NULL ) {
		free(ret);
		return loafers_rc_sys();
	}
	*addr = realloc(ret, strlen(ret) + 1);
	if( *addr == NULL ) {
		free(ret);
		return loafers_rc_sys();
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_get_remote_addr( loafers_conn_t *conn, char **addr ) {
	// The remote address is only available when using BIND
	if( conn->req.cmd != SOCKS_CMD_BIND ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_addr(conn, addr, conn->reply, &conn->reply_avail);
}

loafers_rc_t loafers_get_external_addr( loafers_conn_t *conn, char **addr ) {
	// The external address is only available when using CONNECT
	if( conn->req.cmd != SOCKS_CMD_CONNECT ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_addr(conn, addr, conn->reply, &conn->reply_avail);
}

loafers_rc_t loafers_get_listen_addr( loafers_conn_t *conn, char **addr ) {
	// The listen address is only available when using BIND
	if( conn->req.cmd != SOCKS_CMD_BIND ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_addr(conn, addr, conn->bnd_reply, &conn->bnd_reply_avail);
}

static loafers_rc_t loafers_get_generic_port( loafers_conn_t *conn, in_port_t *port, socks_reply_t *reply, bool *avail_flag ) {
	assert(port != NULL && conn != NULL && reply != NULL && avail_flag != NULL);
	if( !*avail_flag ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	*port = reply->bnd_port;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_get_remote_port( loafers_conn_t *conn, in_port_t *port ) {
	// The remote port is only available when using BIND
	if( conn->req.cmd != SOCKS_CMD_BIND ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_port(conn, port, conn->reply, &conn->reply_avail);
}

loafers_rc_t loafers_get_external_port( loafers_conn_t *conn, in_port_t *port ) {
	// The external port is only available when using CONNECT
	if( conn->req.cmd != SOCKS_CMD_CONNECT ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_port(conn, port, conn->reply, &conn->reply_avail);
}

loafers_rc_t loafers_get_listen_port( loafers_conn_t *conn, in_port_t *port ) {
	// The listen port is only available when using BIND
	if( conn->req.cmd != SOCKS_CMD_BIND ) return loafers_rc(LOAFERS_ERR_NOTAVAIL);
	return loafers_get_generic_port(conn, port, conn->bnd_reply, &conn->bnd_reply_avail);
}

loafers_rc_t loafers_rc_socks( loafers_err_e err, loafers_err_socks_e socks_err ) {
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
				[LOAFERS_ERR_BADSTATE] = "Invalid state machine",
				[LOAFERS_ERR_NOTAVAIL] = "Information not available",
				[LOAFERS_ERR_STREAM] = "Stream error",
				[LOAFERS_ERR_TALLOC] = "Talloc generic error"
			};
			static const size_t noerrors = sizeof(errors) / sizeof(char *);
			loafers_err_e errnum = loafers_errno(err);
			if( errnum >= noerrors ) return "Unknown error";
			return errors[errnum];
		}
	}
}

loafers_rc_t loafers_free_addr_u( socks_atyp_e atyp, socks_addr_u addr ) {
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
			return loafers_rc_sys();
	}
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_conn_alloc( loafers_conn_t **conn ) {
	assert(conn != NULL);

	*conn = malloc(sizeof(loafers_conn_t));
	if( *conn == NULL ) return loafers_rc_sys();
	bzero(*conn, sizeof(loafers_conn_t));
	(*conn)->state = LOAFERS_CONN_UNPREPARED;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_conn_free( loafers_conn_t **conn ) {
	assert(conn != NULL && *conn != NULL);

	loafers_conn_t *c = *conn;
	if( c->ver.methods != NULL ) free(c->ver.methods);
	if( c->buf != NULL ) free(c->buf);
	if( c->data != NULL ) free(c->data);
	loafers_rc_t rc = loafers_free_addr_u(c->req.atyp, c->req.dst_addr);
	loafers_rc_t rc2, rc3;
	rc2 = rc3 = loafers_rc(LOAFERS_ERR_NOERR);
	if( c->reply != NULL ) {
		rc2 = loafers_free_addr_u(c->reply->atyp, c->reply->bnd_addr);
		free(c->reply);
	}
	if( c->bnd_reply != NULL ) {
		rc3 = loafers_free_addr_u(c->bnd_reply->atyp, c->bnd_reply->bnd_addr);
		free(c->bnd_reply);
	}
	free(c);
	*conn = NULL;
	if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	if( loafers_errno(rc2) != LOAFERS_ERR_NOERR ) return rc2;
	if( loafers_errno(rc3) != LOAFERS_ERR_NOERR ) return rc3;
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
	assert(conn != NULL);

	conn->ver.ver = version;
	conn->req.ver = version;

	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_methods( loafers_conn_t *conn, uint8_t nmethods, const socks_method_e methods[static nmethods] ) {
	assert(conn != NULL && methods != NULL);

	if( conn->ver.methods != NULL ) free(conn->ver.methods);
	conn->ver.methods = calloc(sizeof(socks_method_e), nmethods);
	if( conn->ver.methods == NULL ) return loafers_rc_sys();
	memcpy(conn->ver.methods, methods, nmethods * sizeof(socks_method_e));
	conn->ver.nmethods = nmethods;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_command( loafers_conn_t *conn, socks_cmd_e cmd ) {
	assert(conn != NULL);

	conn->req.cmd = cmd;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_set_atyp( loafers_conn_t *conn, socks_atyp_e atyp ) {
	assert(conn != NULL);

	conn->req.atyp = atyp;
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_hostname( loafers_conn_t *conn, const char *hostname, in_port_t port ) {
	assert(conn != NULL && hostname != NULL);

	socks_request_t *req = &conn->req;
	loafers_rc_t rc = loafers_set_atyp(conn, SOCKS_ATYP_HOSTNAME);
	if( loafers_errno(rc) != LOAFERS_ERR_NOERR ) return rc;
	req->dst_port = port;
	if( req->dst_addr.hostname != NULL ) free(req->dst_addr.hostname);
	req->addrsiz = (strlen(hostname) + 1) * sizeof(char);
	req->dst_addr.hostname = malloc(req->addrsiz);
	if( req->dst_addr.hostname == NULL ) return loafers_rc_sys();
	memcpy(req->dst_addr.hostname, hostname, req->addrsiz);
	loafers_set_prepared(conn);
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_set_sockaddr( loafers_conn_t *conn, const struct sockaddr *address ) {
	assert(conn != NULL && address != NULL);

	socks_request_t *req = &conn->req;
	loafers_rc_t rc;
	switch( address->sa_family ) {
		case AF_INET:
			if( loafers_errno(rc = loafers_set_atyp(conn, SOCKS_ATYP_IPV4)) != LOAFERS_ERR_NOERR ) return rc;
			struct sockaddr_in *addr = (struct sockaddr_in *) address;
			req->dst_port = addr->sin_port;
			if( req->dst_addr.ip4 != NULL ) free(req->dst_addr.ip4);
			req->addrsiz = sizeof(struct in_addr);
			req->dst_addr.ip4 = malloc(req->addrsiz);
			if( req->dst_addr.ip4 == NULL ) return loafers_rc_sys();
			memcpy(req->dst_addr.ip4, &addr->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			if( loafers_errno(rc = loafers_set_atyp(conn, SOCKS_ATYP_IPV6)) != LOAFERS_ERR_NOERR ) return rc;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
			req->dst_port = addr6->sin6_port;
			if( req->dst_addr.ip6 != NULL ) free(req->dst_addr.ip6);
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

loafers_rc_t loafers_connbuf_alloc( loafers_conn_t *conn, size_t count ) {
	size_t bufsiz = count * sizeof(uint8_t);
	uint8_t *buf = realloc(conn->buf, bufsiz);
	if( buf == NULL ) return loafers_rc_sys();
	conn->buf = buf;
	conn->bufptr = buf;
	conn->bufremain = bufsiz;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_write( loafers_stream_t *stream, const void *buf, size_t buflen, ssize_t *remain ) {
	assert(stream != NULL && remain != NULL);

	return loafers_raw_write(stream, buf, buflen, remain);
}

loafers_rc_t loafers_stream_read( loafers_stream_t *stream, void *buf, size_t buflen, ssize_t *remain ) {
	assert(stream != NULL && remain != NULL);

	return loafers_raw_read(stream, buf, buflen, remain);
}
