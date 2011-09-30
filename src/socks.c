#include "loafers.h"

#include "_common.h"

loafers_rc_t loafers_connect( loafers_conn_t *conn, loafers_stream_t *control, loafers_stream_t *data ) {
	loafers_rc_t rc;
	socks_version_t *ver = &conn->ver;
	if( loafers_errno(rc = loafers_connbuf_alloc(conn, ver->nmethods + (2 * sizeof(uint8_t)))) != LOAFERS_ERR_NOERR ) return rc;
	uint8_t *buf = conn->buf;
	buf[0] = ver->ver;
	buf[1] = ver->nmethods;
	for( uint8_t i = 0; i < ver->nmethods; i++ )
		buf[i + 2] = ver->methods[i];

	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_conn_write(conn)) != LOAFERS_ERR_NOERR ) return rc;
}
