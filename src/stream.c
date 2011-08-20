#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include <talloc.h>

#include "loafers.h"

#include "_common.h"
#include "_stream.h"

loafers_rc_t loafers_stream_socket_alloc( loafers_stream_t **stream, int sockfd ) {
	assert(stream != NULL);

	loafers_stream_socket_data_t *data = talloc_zero(NULL, loafers_stream_socket_data_t);
	if( data == NULL ) return loafers_rc_sys();
	data->sock = sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_stream_custom_alloc(stream, data, loafers_stream_write_socket, loafers_stream_read_socket, NULL)) != LOAFERS_ERR_NOERR ) return rc;
	talloc_steal(*stream, data);
	return rc;
}

loafers_rc_t loafers_stream_custom_alloc( loafers_stream_t **stream, void *data, loafers_stream_writer_f writer, loafers_stream_reader_f reader, void *error ) {
	assert(stream != NULL);

	loafers_stream_t *s = talloc_zero(NULL, loafers_stream_t);
	if( s == NULL ) return loafers_rc_sys();
	s->write = writer;
	s->read = reader;
	s->data = data;
	s->error = error;
	*stream = s;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

void *loafers_get_stream_error( const loafers_stream_t *stream ) {
	return stream->error;
}

loafers_rc_t loafers_stream_free( loafers_stream_t **stream ) {
	assert(stream != NULL);

	if( talloc_free(*stream) == -1 ) return loafers_rc(LOAFERS_ERR_TALLOC);
	*stream = NULL;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

// TODO: Stream handlers for FILEs.

static loafers_rc_t loafers_stream_write_socket( void *d, const void *buf, size_t buflen, ssize_t *remain, void *error ) {
	(void) error;
	assert(d != NULL && remain != NULL);

	loafers_stream_socket_data_t *data = (loafers_stream_socket_data_t *) d;
	size_t bufremain = buflen;
	const void *bufptr = buf;

	loafers_rc_t rc = loafers_rc(LOAFERS_ERR_NOERR);
	do {
		ssize_t ret = write(*((int *) data), bufptr, bufremain);
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

	*remain = bufremain;
	return rc;
}

static loafers_rc_t loafers_stream_read_socket( void *d, void *buf, size_t buflen, ssize_t *remain, void *error ) {
	(void) error;
	assert(d != NULL && remain != NULL);

	loafers_stream_socket_data_t *data = (loafers_stream_socket_data_t *) d;
	size_t bufremain = buflen;
	void *bufptr = buf;

	loafers_rc_t rc = loafers_rc(LOAFERS_ERR_NOERR);
	do {
		ssize_t ret = read(*((int *) data), bufptr, bufremain);
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

	*remain = bufremain;
	return rc;
}

loafers_rc_t loafers_conn_write( loafers_stream_t *stream, loafers_conn_t *conn ) {
	ssize_t remain;
	loafers_rc_t rc = stream->write(stream->data, conn->bufptr, conn->bufremain, &remain, stream->error);
	conn->bufptr += conn->bufremain - remain;
	conn->bufremain -= remain;
	return rc;
}

loafers_rc_t loafers_conn_read( loafers_stream_t *stream, loafers_conn_t *conn ) {
	ssize_t remain;
	loafers_rc_t rc = stream->read(stream->data, conn->bufptr, conn->bufremain, &remain, stream->error);
	conn->bufptr += conn->bufremain - remain;
	conn->bufremain -= remain;
	return rc;
}
