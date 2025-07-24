#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include <stdint.h>
#include "crypto.h"
#include "tee_core_compat.h"
#include "puf_handler.h"
#include "crosscon_hv_config.h" //Needed for UUID hashing - identity scoping

#define RESPONSE_PRE_HASH_SIZE (PUF_RESPONSE_SIZE + CHALLENGE_SIZE + TEE_UUID_LEN)

int get_response_to_challenge(uint8_t *challenge, TEE_BigInt *response);
int get_commited_value(TEE_BigInt *response_0, TEE_BigInt *response_1, TEE_ECPoint *commitment);
int extract_raw_commitment(TEE_ECPoint *commitment, uint8_t *raw_commitment);

#endif /* PUF_PROVER_H */
