#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include "fsl_puf.h"
#include "flash_handler.h"
#include "mbedtls/ecp.h"

#define NUM_RANDOM_NUMBERS 2
#define RANDOM_NUMBER_SIZE_BYTES 32
#define PUF_SLOT 0
#define CONSTANT_FOR_H_GENERATOR 123456789

/**
 * @brief Initializes and optionally enrolls and starts the PUF module.
 *
 * @param puf               Pointer to PUF instance.
 * @param pufConfig         PUF configuration structure.
 * @param activation_code   Buffer to store or read the activation code.
 * @param activation_code_size Size of the activation code buffer.
 * @param flash_area        Pointer to flash area for storing activation code.
 * @param flash_dev         Flash device used for read/write operations.
 * @param writeToFlash      Set to true for enrollment; false to reuse stored code.
 * @return 0 on success, non zero on failure.
 */
int initialize_and_start_puf(PUF_Type *puf, puf_config_t pufConfig,
                          uint8_t *activation_code, size_t activation_code_size,
                          const struct flash_area *flash_area,
                          const struct device *flash_dev, bool writeToFlash);

/**
* @brief Retrieves the PUF key and optionally stores the key code in flash.
*
* @param puf               Pointer to PUF instance.
* @param activation_code   Pointer to activation code buffer.
* @param activation_code_size Size of activation code.
* @param flash_area        Flash area for key code storage.
* @param flash_dev         Flash device.
* @param writeToFlash      True if key code should be written to flash.
* @param outputBuffer      Output buffer for the intrinsic key (optional).
* @return 0 on success, non zero on failure.
*/
int get_puf_key(PUF_Type *puf, uint8_t *activation_code, size_t activation_code_size,
              const struct flash_area *flash_area, const struct device *flash_dev,
              bool writeToFlash, uint8_t *outputBuffer);

/**
* @brief Deinitializes the PUF instance.
*
* @param puf           Pointer to PUF instance.
* @param pufConfig     PUF configuration structure.
*/
void puf_deinit(PUF_Type *puf, puf_config_t pufConfig);

/**
* @brief Computes the response from PUF for a given challenge.
*
* @param c             Input challenge.
* @param c_size        Size of the challenge.
* @param r             Output MPI result of the hashed response.
* @param puf           PUF instance.
* @param activation_code Activation code buffer.
* @param activation_code_size Activation code size.
* @param flash_area    Flash area used for key code.
* @param flash_dev     Flash device.
* @param writeToFlash  Whether to regenerate and store key code.
* @return 0 on success, non zero on failure.
*/
int get_response_to_challenge(const uint8_t *c, size_t c_size, mbedtls_mpi *r,
                            PUF_Type *puf, uint8_t *activation_code,
                            size_t activation_code_size,
                            const struct flash_area *flash_area,
                            const struct device *flash_dev, bool writeToFlash);

/**
* @brief Initializes ECC group and point h.
*
* @param grp           ECC group to initialize.
* @param h             ECC point h to compute.
* @param C             ECC point C to initialize.
* @return 0 on success, non zero on failure.
*/
int init_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *C);

/**
* @brief Performs ECC enrollment operation with two challenges and stores resulting point C.
*
* @param grp           ECC group.
* @param h             Precomputed ECC point h.
* @param C             Output ECC commitment point C.
* @param c1, c2        Challenge 1 and 2 buffers.
* @param c1_size, c2_size Size of challenge buffers.
* @param puf           PUF instance.
* @param pufConfig     PUF Config instance.
* @param activation_code Activation code.
* @param activation_code_size Size of activation code.
* @param flash_area    Flash area used.
* @param flash_dev     Flash device.
* @param writeToFlash  Whether to store new key code.
* @return 0 on success, non zero on failure.
*/
int perform_enrollment(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *C,
                      const uint8_t *c1, size_t c1_size,
                      const uint8_t *c2, size_t c2_size,
                      PUF_Type *puf, puf_config_t pufConfig, uint8_t *activation_code,
                      size_t activation_code_size,
                      const struct flash_area *flash_area,
                      const struct device *flash_dev, bool writeToFlash);

/**
* @brief Adds and multiplies values modulo a given prime.
*
* @param mpiValue_1    Value to add.
* @param mpiValue_2    Value to multiply.
* @param mpiValue_R    Second value to multiply.
* @param mpiValue_p    Modulo value (usually EC group prime).
* @param result        Output result.
* @return 0 on success, non zero on error.
*/
int add_mul_mod(mbedtls_mpi *mpiValue_1, mbedtls_mpi *mpiValue_2,
                mbedtls_mpi *mpiValue_R, mbedtls_mpi *mpiValue_p,
                mbedtls_mpi *result);



/**
* @brief Performs PUF-based ECC authentication and response proof generation.
*
* @param grp           ECC group.
* @param g             Generator point g.
* @param h             Secondary generator point h.
* @param proof         Output ECC proof point.
* @param C             Commitment point.
* @param result_v      Output response scalar v.
* @param result_w      Output response scalar w.
* @param nonce         Output nonce used in hashing.
* @param c1, c2        Challenges used for authentication.
* @param c1_size, c2_size Sizes of challenges.
* @param puf           PUF instance.
* @param pufConfig     PUF Config instance.
* @param activation_code Activation code buffer.
* @param activation_code_size Size of activation code.
* @param flash_area    Flash area used for flash reads.
* @param flash_dev     Flash device used.
* @param commitment_hex Pointer of Char to store the Commitment
* @param commitment_size Size of Commitment
* @return 0 on success, non zero on failure.
*/
int perform_authentication(mbedtls_ecp_group *grp, mbedtls_ecp_point *g, mbedtls_ecp_point *h,
                          mbedtls_ecp_point *proof, mbedtls_ecp_point *C,
                          mbedtls_mpi *result_v, mbedtls_mpi *result_w,
                          mbedtls_mpi *nonce,
                          const uint8_t *c1, size_t c1_size,
                          const uint8_t *c2, size_t c2_size,
                          PUF_Type *puf, puf_config_t pufConfig, uint8_t *activation_code,
                          size_t activation_code_size,
                          const struct flash_area *flash_area,
                          const struct device *flash_dev, const char *commitment_hex, size_t commitment_size);


#endif /* PUF_PROVER_H */
