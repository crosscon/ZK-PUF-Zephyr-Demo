#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include <stdint.h>
#include "crypto.h"
#include "tee_core_compat.h"
#include "puf_handler.h"

#define CHALLENGE_SIZE 32

#ifndef PUF_RESPONSE_SIZE
#define PUF_RESPONSE_SIZE 128
#endif

#define RESPONSE_PRE_HASH_SIZE CHALLENGE_SIZE+PUF_RESPONSE_SIZE

int get_response_to_challenge(uint8_t *challenge, TEE_BigInt *response);
int get_commited_value(TEE_BigInt *response_0, TEE_BigInt *response_1, TEE_ECPoint *commitment);
int extract_raw_commitment(TEE_ECPoint *commitment, uint8_t *raw_commitment);

_Static_assert(PUF_RESPONSE_SIZE >= 128, "PUF Response size should be greater than 128 bits");

#endif /* PUF_PROVER_H */
