#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <talloc.h>

#include "loafers.h"

#include "_common.h"
#include "_stream.h"

loafers_rc_t loafers_stream_socket_alloc( loafers_stream_t **stream, int sockfd ) {
	assert(stream != NULL);

	int *sockptr;
	sockptr = talloc_ptrtype(NULL, sockptr);
	if( sockptr == NULL ) return loafers_rc_sys();
	*sockptr = sockfd;
	loafers_rc_t rc;
	if( loafers_errno(rc = loafers_stream_custom_alloc(stream, sockptr, loafers_stream_write_socket, loafers_stream_read_socket, loafers_stream_close_socket)) != LOAFERS_ERR_NOERR ) {
		(void) talloc_free(sockptr);
		return rc;
	}
	(void) talloc_steal(*stream, sockptr);
	return rc;
}

loafers_rc_t loafers_stream_FILE_alloc( loafers_stream_t **stream, FILE *file ) {
	assert(stream != NULL);

	return loafers_stream_custom_alloc(stream, file, loafers_stream_write_FILE, loafers_stream_read_FILE, loafers_stream_close_FILE);
}

loafers_rc_t loafers_stream_custom_alloc( loafers_stream_t **stream, void *data, loafers_stream_writer_f writer, loafers_stream_reader_f reader, loafers_stream_closer_f closer ) {
	assert(stream != NULL);

	loafers_stream_t *s = talloc_ptrtype(NULL, s);
	if( s == NULL ) return loafers_rc_sys();
	memset(s, 0, sizeof(*s));
	// TODO: UDP
	s->udp = false;
	s->write = writer;
	s->read = reader;
	s->close = closer;
	s->data = data;
	*stream = s;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_close( loafers_stream_t **s ) {
	assert(s != NULL);

	loafers_stream_t *stream = *s;
	loafers_rc_t rc;
	while( stream->state.close != LOAFERS_CLOSE_DONE ) {
		switch( stream->state.close ) {
			case LOAFERS_CLOSE_CLOSING:
				if( stream->close != NULL && loafers_errno(rc = stream->close(stream->data)) != LOAFERS_ERR_NOERR ) return rc;
				stream->state.close = LOAFERS_CLOSE_FREEING;
			case LOAFERS_CLOSE_FREEING:
				if( talloc_free(stream) == -1 ) return loafers_rc(LOAFERS_ERR_TALLOC);
				stream->state.close = LOAFERS_CLOSE_DONE;
				break;
			default:
				assert(false);
				errno = EINVAL;
				return loafers_rc_sys();
		}
	}
	*s = NULL;
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
	// OPTIMIZE: Don't delegate to loafers_write_socket and the fflush can go.
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
	// OPTIMIZE: Don't delegate to loafers_write_socket and the fflush can go.
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

// TODO: Return a count rather than a remain
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
#endif /* NDEBUG */
	return rc;
}

// TODO: Return a count rather than a remain
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

loafers_rc_t loafers_stream_flush( loafers_stream_t *stream ) {
	if( stream->write == NULL ) return loafers_rc(LOAFERS_ERR_NOT_SUPPORTED);
	if( stream->wpacket == NULL ) return loafers_rc(LOAFERS_ERR_NOERR);
	do {
		loafers_rc_t rc;
		switch( stream->state.flush ) {
			case LOAFERS_FLUSH_WRITING: {
				ssize_t remain;
				do {
					if( loafers_errno(rc = stream->write(stream->data, stream->wpacketptr, stream->wpacketlen, &remain)) != LOAFERS_ERR_NOERR ) return rc;
					stream->wpacketptr += stream->wpacketlen - remain;
					stream->wpacketlen = remain;
#ifndef NDEBUG
					// If we didn't get the data out in one shot and we're doing UDP, then we did it wrong.
					if( stream->udp ) assert(remain == 0);
#endif /* NDEBUG */
				} while( remain != 0 );
				assert(stream->wpacketlen == 0);
				stream->state.flush = LOAFERS_FLUSH_PURGING;
			}
			case LOAFERS_FLUSH_PURGING:
				if( loafers_errno(rc = loafers_stream_purge(stream)) != LOAFERS_ERR_NOERR ) return rc;
				stream->state.flush = LOAFERS_FLUSH_WRITING;
				break;
			default:
				assert(false);
				errno = EINVAL;
				return loafers_rc_sys();
		}
	} while( stream->state.flush != LOAFERS_FLUSH_WRITING );
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_purge( loafers_stream_t *stream ) {
	if( stream->wpacket == NULL ) return loafers_rc(LOAFERS_ERR_NOERR);
	if( talloc_free(stream->wpacket) == -1 ) return loafers_rc(LOAFERS_ERR_TALLOC);
	stream->wpacket = stream->wpacketptr = NULL;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_write( loafers_stream_t *stream, const void *buf, size_t buflen ) {
	if( stream->write == NULL ) return loafers_rc(LOAFERS_ERR_NOT_SUPPORTED);
	size_t wpacketlen = buflen + stream->wpacketlen;
	// OPTIMIZE: This can be optimized with a talloc_pool
	void *wpacket = talloc_realloc(stream, stream->wpacket, void, wpacketlen);
	if( wpacket == NULL ) return loafers_rc_sys();
	loafers_talloc_name(wpacket);
	stream->wpacket = stream->wpacketptr = wpacket;
	wpacket += stream->wpacketlen;
	memcpy(wpacket, buf, buflen);
	stream->wpacketlen = wpacketlen;
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_stream_read( loafers_stream_t *stream, void *buf, size_t buflen, size_t *count ) {
	ssize_t remain = buflen;
	loafers_rc_t rc = stream->read(stream->data, buf, buflen, &remain);
	assert(remain >= 0);
	if( count != NULL ) *count = buflen - remain;
#ifndef NDEBUG
	if( count == NULL ) assert(remain == 0);
#endif /* NDEBUG */
	return rc;
}

loafers_rc_t loafers_write( loafers_stream_t *stream, const void *buf, size_t buflen ) {
	assert(stream != NULL);

	loafers_rc_t rc;
	do {
		switch( stream->state.write ) {
			case LOAFERS_WRITE_PURGING:
				if( loafers_errno(rc = loafers_stream_purge(stream)) != LOAFERS_ERR_NOERR ) return rc;
				stream->state.write = LOAFERS_WRITE_WRITING;
			case LOAFERS_WRITE_WRITING:
				if( loafers_errno(rc = loafers_stream_write(stream, buf, buflen)) != LOAFERS_ERR_NOERR ) return rc;
				stream->state.write = LOAFERS_WRITE_FLUSHING;
			case LOAFERS_WRITE_FLUSHING:
				if( loafers_errno(rc = loafers_stream_flush(stream)) != LOAFERS_ERR_NOERR ) return rc;
				stream->state.write = LOAFERS_WRITE_PURGING;
				break;
			default:
				assert(false);
				errno = EINVAL;
				return loafers_rc_sys();
		}
	} while( stream->state.write != LOAFERS_WRITE_PURGING );
	return loafers_rc(LOAFERS_ERR_NOERR);
}

loafers_rc_t loafers_read( loafers_stream_t *stream, void *buf, size_t buflen, size_t *count ) {
	assert(stream != NULL);

	return loafers_stream_read(stream, buf, buflen, count);
}
