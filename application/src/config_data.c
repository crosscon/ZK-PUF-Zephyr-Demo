#include "config_data.h"

const char *commitment_hex = "0485E41D73D71C62636D6D8FCE2349382FB2FBCFD618229431957B551F8F3F84B9EFC43EAF541F981F05AB97820F0DE552E77F5924311A3450F37BD0DC9AD16693"; // Update before running authentication

const uint8_t c1[CHALLENGE_SIZE] = {
    0x3C, 0xA1, 0xF4, 0x92,
    0x57, 0xB8, 0x0E, 0x6D,
    0x1F, 0xA9, 0xC3, 0xE7,
    0x74, 0x90, 0x12, 0xAD
};

const uint8_t c2[CHALLENGE_SIZE] = {
    0xFF, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0x00,
    0x00, 0xFF, 0x00, 0xFF,
    0x00, 0xFF, 0x00, 0xFF
};


//ECC points 
puf_config_t puf_config_instance;

mbedtls_ecp_group ecp_grp;
mbedtls_ecp_point h_point, C_point;

bool puf_and_ecc_intialisation = false;


//activation code
__attribute__((aligned(16))) uint8_t activation_code_buffer[PUF_ACTIVATION_CODE_SIZE];

//flash parameters
const struct flash_area *flash_area_instance = NULL;
const struct device *flash_dev_instance= NULL;
