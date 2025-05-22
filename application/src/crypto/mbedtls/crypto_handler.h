#ifndef CRYPTO_HANDLER_H
#define CRYPTO_HANDLER_H

#include "mbedtls/bignum.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecp.h"

extern mbedtls_ecp_group grp;
extern mbedtls_ecp_point h;
extern mbedtls_ecp_point g;

int init_crypto(void);
int get_random_mpi(mbedtls_mpi *X);
void log_mpi_hex(const char *label, const mbedtls_mpi *X);

#endif /* CRYPTO_HANDLER_H */
