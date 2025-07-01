#ifndef TEE_CORE_COMPAT_H
#define TEE_CORE_COMPAT_H

#include "tee_internal_api.h"

/* BigInt abstraction */
#define TEE_MAX_BIGINT_BITS 2048
#define TEE_MAX_BIGINT_BYTES (TEE_MAX_BIGINT_BITS / 8)

/* Forward declaration (backend defined in crypto_handler.c) */
typedef struct TEE_BigInt TEE_BigInt;

/* BigInt operations (backend defined in crypto_handler.c) */
TEE_BigInt* TEE_BigIntAlloc(void);  // Required for forward declaration
void        TEE_BigIntFree(TEE_BigInt *X);
TEE_Result  TEE_BigIntConvertFromBytes(TEE_BigInt *X, const uint8_t *buf, size_t len);
TEE_Result  TEE_BigIntConvertToBytes(const TEE_BigInt *X, uint8_t *buf, size_t len);
TEE_Result  TEE_BigIntMul(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *B);
TEE_Result  TEE_BigIntAdd(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *B);
TEE_Result  TEE_BigIntMod(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *N);
TEE_Result  TEE_BigIntGenerateRandom(TEE_BigInt *X, size_t num_bytes,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng);
size_t      TEE_BigIntSizeInBytes(const TEE_BigInt *X);

#endif // TEE_CORE_COMPAT_H
