#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#ifdef __cplusplus
extern "C" {
#endif

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int rng_initialized = 0;

/**
 * @brief Computes SHA-256 hash of input data.
 *
 * @param data       Pointer to input data.
 * @param data_len   Length of input data.
 * @param output     Output buffer (32 bytes) for SHA-256 hash.
 */
void sha256_hash(const unsigned char *data, size_t data_len, unsigned char *output);

/**
 * @brief Simple fallback random number generator using rand().
 *
 * @param rng_state  Unused parameter (can be NULL).
 * @param output     Buffer to store generated random bytes.
 * @param len        Number of random bytes to generate.
 * @return 0 on success.
 */
int rand_function(void *rng_state, unsigned char *output, size_t len);

/**
 * @brief Serializes an EC point to a buffer.
 *
 * @param grp        EC group the point belongs to.
 * @param C          EC point to serialize.
 * @param buf        Buffer to write the serialized point.
 * @param buf_size   Size of the buffer.
 * @return Number of bytes written on success, -1 on failure.
 */
size_t export_commitment(mbedtls_ecp_group *grp, const mbedtls_ecp_point *C, uint8_t *buf, size_t buf_size);

/**
 * @brief Deserializes an EC point from a buffer.
 *
 * @param grp        EC group to read the point into.
 * @param buf        Buffer containing the serialized EC point (65 bytes expected).
 * @param P          Destination EC point.
 * @return length on success, -1 on failure.
 */
int import_commitment(mbedtls_ecp_group *grp, const uint8_t *buf, mbedtls_ecp_point *P);

/**
 * @brief Generates two random 256-bit (32-byte) numbers using CTR_DRBG.
 *
 * @param num        Output MPI for the first random number.
 * @param num2       Output MPI for the second random number.
 * @return 0 on success, 1 on error.
 */
int generate_random_numbers(mbedtls_mpi *num, mbedtls_mpi *num2);

/**
 * @brief Prints a big number (MPI) in hexadecimal.
 *
 * @param label      Label to print before the number.
 * @param value      MPI value to print.
 */
void print_mpi(const char *label, const mbedtls_mpi *value);

/**
 * @brief Prints an EC point in uncompressed hexadecimal form.
 *
 * @param label      Label to print before the point.
 * @param grp        EC group the point belongs to.
 * @param point      EC point to print.
 */
void print_ecp_point(const char *label, const mbedtls_ecp_group *grp, const mbedtls_ecp_point *point);

/**
 * @brief Initializes the global CTR_DRBG context for secure random number generation.
 *
 * This must be called once at startup before using generateRandomNumbers().
 *
 * @return 0 on success, non-zero on error.
 */
int init_random_generator(void);

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * @param hex       Null-terminated string containing hexadecimal characters.
 * @param out       Output buffer where the bytes will be stored.
 * @param out_size  Size of the output buffer.
 * @return int      0 on success, non zero on failure
 */
int hex_string_to_bytes(const char *hex, uint8_t *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H
