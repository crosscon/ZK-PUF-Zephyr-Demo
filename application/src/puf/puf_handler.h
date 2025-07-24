#ifndef PUF_HANDLER_H
#define PUF_HANDLER_H

#include "tee_internal_api.h"

#ifndef CHALLENGE_SIZE
#define CHALLENGE_SIZE 32
#endif

#ifndef PUF_RESPONSE_SIZE
#define PUF_RESPONSE_SIZE 128
#endif

/**
 * @brief Initializes the PUF module.
 *
 * May perform enrollment or hardware setup depending on the implementation.
 *
 * @return TEE_SUCCESS on success, or error code on failure.
 */
TEE_Result init_puf(void);

/**
 * @brief Retrieves a derived key from the PUF
 *
 * @param puf_key Output buffer for the derived key (must be PUF_RESPONSE_SIZE bytes).
 * @return TEE_SUCCESS on success, or error code on failure.
 */
TEE_Result puf_get_key(uint8_t *puf_key);

/**
 * @brief Securely wipes the key from memory.
 *
 * Overwrites the buffer with zeros and verifies wipe.
 */
TEE_Result puf_flush_key(uint8_t *puf_key);

_Static_assert(PUF_RESPONSE_SIZE >= 128, "PUF Response size should be greater than 128 bits");

#endif /* PUF_HANDLER_H */
