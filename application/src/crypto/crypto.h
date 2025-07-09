#ifndef CRYPTO_H
#define CRYPTO_H

#include "tee_core_compat.h"
#include "mbedtls/ecp.h"

extern TEE_ECPoint *h;
extern TEE_ECPoint *g;
extern TEE_ECCurve *grp;

int init_crypto(void);
int get_random_bigint(TEE_BigInt *X);
void log_bigint_hex(const char *label, const TEE_BigInt *X);
void log_ecp_point(const char *label, const TEE_ECPoint *P);

#endif /* CRYPTO_H */
