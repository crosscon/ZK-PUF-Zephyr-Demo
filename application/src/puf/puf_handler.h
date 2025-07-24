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
 * @brief Retrieves a derived key from the PUF, optionally scoped by a label.
 *
 * For weak PUFs, this label may be used as a salt in a hash function together with
 * the intrinsic PUF response (e.g., TA UUID or purpose).
 *
 * For strong PUFs, the label may be used internally by the hardware to derive
 * a distinct key using built-in diversification mechanisms.
 *
 * @param label Optional label or purpose string (can be NULL for default key).
 * @param label_len Length of the label in bytes.
 * @param puf_key Output buffer for the derived key (must be PUF_RESPONSE_SIZE bytes).
 * @return TEE_SUCCESS on success, or error code on failure.
 */
TEE_Result puf_get_key(const uint8_t *label, size_t label_len, uint8_t *puf_key);

/**
 * @brief Securely wipes the key from memory.
 *
 * Overwrites the buffer with zeros and verifies wipe.
 */
TEE_Result puf_flush_key(uint8_t *puf_key);

_Static_assert(PUF_RESPONSE_SIZE >= 128, "PUF Response size should be greater than 128 bits");

#endif /* PUF_HANDLER_H */
