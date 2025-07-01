#ifndef CRYPTO_H
#define CRYPTO_H

#include "tee_core_compat.h"
#include "mbedtls/ecp.h"

extern mbedtls_ecp_point h;
extern mbedtls_ecp_point g;
extern mbedtls_ecp_group grp;

int init_crypto(void);
int get_random_bigint(TEE_BigInt *X);
void log_bigint_hex(const char *label, const TEE_BigInt *X);

#endif /* CRYPTO_H */
