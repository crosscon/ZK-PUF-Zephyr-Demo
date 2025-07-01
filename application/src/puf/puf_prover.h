#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include <stdint.h>
#include "crypto.h"
#include "tee_core_compat.h"

#define CHALLENGE_SIZE 16

#define NONCE_SIZE 16

#ifndef PUF_KEY_SIZE
#define PUF_KEY_SIZE 32
#endif

#define RESPONSE_SIZE CHALLENGE_SIZE+PUF_KEY_SIZE

int get_response_to_challenge(uint8_t *challenge, TEE_BigInt *response);
int get_commited_value(TEE_BigInt *response_0, TEE_BigInt *response_1, mbedtls_ecp_point *commitment);
int extract_raw_commitment(mbedtls_ecp_point *commitment, uint8_t *raw_commitment);
int log_ecp_point(const char *label, const mbedtls_ecp_point *P);

#endif /* PUF_PROVER_H */
