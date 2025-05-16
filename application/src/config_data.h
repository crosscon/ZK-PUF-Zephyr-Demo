// config_data.h
#ifndef CONFIG_DATA_H
#define CONFIG_DATA_H

#include <stdint.h>
#include "mbedtls/ecp.h"
#include "puf_prover.h"


#define ENROLLMENT_IS_UP 1
#define COMMITMENT_BUFFER_SIZE 65
#define CHALLENGE_SIZE 16

// Commitment string declaration
extern const char *commitment_hex;

// Challenge arrays declaration
extern const uint8_t c1[CHALLENGE_SIZE];
extern const uint8_t c2[CHALLENGE_SIZE];


//ECC points 
extern puf_config_t puf_config_instance;

extern mbedtls_ecp_group ecp_grp;
extern mbedtls_ecp_point h_point, C_point;

extern bool puf_and_ecc_intialisation;


//activation code for puf
extern __attribute__((aligned(16))) uint8_t activation_code_buffer[PUF_ACTIVATION_CODE_SIZE];

//flash parameters
extern const struct flash_area *flash_area_instance;
extern const struct device *flash_dev_instance;

#endif // CONFIG_DATA_H
