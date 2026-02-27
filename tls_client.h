#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H
#include <stdint.h>
#include <stddef.h>

extern int tls_verbose;

#define MAX_HOSTNAME  256  /* DNS max 253 + NUL + slack */

/* Opaque session type for TLS 1.3 resumption */
typedef struct tls_session tls_session;

uint8_t *do_https_get(const char *host, int port, const char *path, size_t *out_len);
uint8_t *do_https_get_session(const char *host, int port, const char *path,
                               size_t *out_len, tls_session **session);
void tls_session_free(tls_session *s);

#endif
