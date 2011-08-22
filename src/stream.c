#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <talloc.h>

#include "loafers.h"

#include "_common.h"
#include "_stream.h"

loafers_rc_t loafers_stream_socket_alloc( loafers_stream_t **stream, int sockfd ) {
	assert(stream != NULL);

	int *sockptr = talloc(NULL, int);
	if( sockptr == NULL ) return loafers_rc_sys();
	*sockptr = sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_stream_custom_alloc(stream, sockptr, loafers_stream_write_socket, loafers_stream_read_socket, loafers_stream_close_socket)) != LOAFERS_ERR_NOERR ) return rc;
	(void) talloc_steal(*stream, sockptr);
	return rc;
}

loafers_rc_t loafers_stream_FILE_alloc( loafers_stream_t **stream, FILE *file ) {
	assert(stream != NULL);

	return loafers_stream_custom_alloc(stream, file, loafers_stream_write_FILE, loafers_stream_read_FILE, loafers_stream_close_FILE);
}

loafers_rc_t loafers_stream_custom_alloc( loafers_stream_t **stream, void *data, loafers_stream_writer_f writer, loafers_stream_reader_f reader, loafers_stream_closer_f closer ) {
	assert(stream != NULL);

	loafers_stream_t *s = talloc_zero(NULL, loafers_stream_t);
	if( s == NULL ) return loafers_rc_sys();
	s->write = writer;
	s->read = reader;
	s->close = closer;
	s->data = data;
	*stream = s;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_close( loafers_stream_t **stream ) {
	assert(stream != NULL);

	loafers_rc_t rc;
	if( loafers_errno(rc = (*stream)->close((*stream)->data)) != LOAFERS_ERR_NOERR ) return rc;
	if( talloc_free(*stream) == -1 ) return loafers_rc(LOAFERS_ERR_TALLOC);
	*stream = NULL;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_stream_close_FILE( void *data ) {
	assert(data != NULL);

	if( fclose((FILE *) data) == EOF ) return loafers_rc_sys();
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_stream_write_FILE( void *data, const void *buf, size_t buflen, ssize_t *remain ) {
	assert(data != NULL);

	FILE *f = (FILE *) data;
	int fd = fileno(f);
	flockfile(f);
	// This can be easily optimized if necessary.
	fflush(f);
	loafers_rc_t rc = loafers_stream_write_socket(&fd, buf, buflen, remain);
	funlockfile(f);
	return rc;
}

static loafers_rc_t loafers_stream_read_FILE( void *data, void *buf, size_t buflen, ssize_t *remain ) {
	assert(data != NULL);

	FILE *f = (FILE *) data;
	int fd = fileno(f);
	flockfile(f);
	// This can be easily optimized if necessary.
	fflush(f);
	loafers_rc_t rc = loafers_stream_read_socket(&fd, buf, buflen, remain);
	funlockfile(f);
	return rc;
}

static loafers_rc_t loafers_stream_close_socket( void *data ) {
	assert(data != NULL);

	if( close(*((int *) data)) == -1 ) return loafers_rc_sys();
	return loafers_rc(LOAFERS_ERR_NOERR);
}

static loafers_rc_t loafers_stream_write_socket( void *data, const void *buf, size_t buflen, ssize_t *remain ) {
	assert(data != NULL);

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
		} else if( ret == 0 && buflen == 0 ) {
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	if( remain != NULL ) *remain = bufremain;
#ifndef NDEBUG
	if( remain == NULL ) assert(bufremain == 0);
#endif
	return rc;
}

static loafers_rc_t loafers_stream_read_socket( void *data, void *buf, size_t buflen, ssize_t *remain ) {
	assert(data != NULL);

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
			if( buflen != 0 ) rc = loafers_rc(LOAFERS_ERR_EOF);
			break;
		}
		bufremain -= ret;
		bufptr += ret;
	} while( bufremain != 0 );

	if( remain != NULL ) *remain = bufremain;
	return rc;
}

loafers_rc_t loafers_raw_write( loafers_stream_t *stream, const void *buf, size_t buflen, ssize_t *remain ) {
	return stream->write(stream->data, buf, buflen, remain);
}

loafers_rc_t loafers_raw_read( loafers_stream_t *stream, void *buf, size_t buflen, ssize_t *remain ) {
	return stream->read(stream->data, buf, buflen, remain);
}

loafers_rc_t loafers_stream_write( loafers_stream_t *stream, const void *buf, size_t buflen, ssize_t *remain ) {
	assert(stream != NULL);

	return loafers_raw_write(stream, buf, buflen, remain);
}

loafers_rc_t loafers_stream_read( loafers_stream_t *stream, void *buf, size_t buflen, ssize_t *remain ) {
	assert(stream != NULL);

	return loafers_raw_read(stream, buf, buflen, remain);
}
