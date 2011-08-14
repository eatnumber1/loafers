#ifndef ___LOAFERS_H__
#define ___LOAFERS_H__

static const char *socks_strerror( loafers_err_socks_e err );

static loafers_rc_t loafers_free_addr_u( socks_atyp_e atyp, socks_addr_u addr );

static void loafers_set_prepared( loafers_conn_t *conn );
static loafers_rc_t loafers_set_atyp( loafers_conn_t *conn, socks_atyp_e atyp );

#endif
