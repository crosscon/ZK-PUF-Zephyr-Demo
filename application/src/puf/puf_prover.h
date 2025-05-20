#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include "fsl_puf.h"
#include "flash_handler.h"

/**
 * @brief Initialize the PUF prover.
 *
 * This function initializes the PUF Prover logic and then
 * either enrolls and saves the activation code to flash (if writeToFlash is true)
 * or reads the activation code from flash.
 *
 * @param puf                  Pointer to the PUF instance.
 * @param activation_code      Buffer where the activation code will be stored.
 * @param activation_code_size Size of the activation code in bytes.
 * @param flash_dev            Pointer to the flash device to be used.
 * @param flash_area           Pointer to the flash area structure to be used.
 * @param writeToFlash         True to enroll and write the activation code,
 *                             false to read it from flash.
 *
 * @return 0 on success, negative error code on failure.
 */
int PUF_Prover_Initialize(PUF_Type *puf,
                          uint8_t *activation_code,
                          size_t activation_code_size,
                          const struct flash_area *flash_area,
                          const struct device *flash_dev,
                          bool writeToFlash);

#endif /* PUF_PROVER_H */
